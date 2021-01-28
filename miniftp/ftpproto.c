#include"ftpproto.h"
#include"privsock.h"
#include"tunable.h"


static int port_active(session_t *sess);
static int pasv_active(session_t *sess);
static int get_transfer_fd(session_t *sess);

static void do_user(session_t *sess);
static void do_pass(session_t *sess);
static void do_feat(session_t *sess);
static void do_pwd(session_t *sess);
static void do_type(session_t *sess);
static void do_port(session_t *sess);
static void do_list(session_t *sess);
static void do_pasv(session_t *sess);

static void do_cwd(session_t *sess);
static void do_cdup(session_t *sess);
static void do_mkd(session_t *sess);
static void do_dele(session_t *sess);
static void do_rmd(session_t *sess);
static void do_size(session_t *sess);
static void do_rnfr(session_t *sess);
static void do_rnto(session_t *sess);

//上传下载
static void do_stor(session_t *sess);
static void do_retr(session_t *sess);

//空闲断开函数
void handle_alarm_timeout(int sig);
void handle_sigalrm(int sig);
void start_cmdio_alarm();
void start_data_alarm();

typedef struct ftpcmd 
{
	const char *cmd;
	void (*cmd_handler)(session_t *sess);
} ftpcmd_t;


static ftpcmd_t ctrl_cmds[] = 
{	
	{"USER", do_user},
	{"PASS", do_pass},
	{"FEAT", do_feat},
	{"PWD" , do_pwd },
	{"TYPE", do_type},
	{"PORT", do_port},
	{"LIST", do_list},
	{"PASV", do_pasv},

	{"CWD" , do_cwd },
	{"CDUP", do_cdup},
	{"MKD",  do_mkd },
	{"DELE", do_dele},
	{"RMD",  do_rmd },
	{"SIZE", do_size},
	{"RNFR", do_rnfr},
	{"RNTO", do_rnto},

	{"STOR", do_stor},
	{"RETR", do_retr}
};


session_t *p_sess;

//空闲断开函数
void handle_alarm_timeout(int sig)
{
	shutdown(p_sess->ctrl_fd, SHUT_RD);
	ftp_reply(p_sess, FTP_IDLE_TIMEOUT, "Timeout.");
	shutdown(p_sess->ctrl_fd, SHUT_WR);
	exit(EXIT_SUCCESS);
}

void handle_sigalrm(int sig)
{
	if(!p_sess->data_process)
	{
		ftp_reply(p_sess, FTP_DATA_TIMEOUT, "Data timeout. Reconnect. Sorry.");
		exit(EXIT_FAILURE);
	}
	p_sess->data_process = 0;
	start_data_alarm();
}

void start_cmdio_alarm()
{
	if(tunable_idle_session_timeout > 0)
	{
		signal(SIGALRM, handle_alarm_timeout);
		alarm(tunable_idle_session_timeout);
	}
}

void start_data_alarm()
{
	if(tunable_data_connection_timeout > 0)
	{
		signal(SIGALRM, handle_sigalrm);
		alarm(tunable_data_connection_timeout);
	}
	else if(tunable_idle_session_timeout > 0)
	{
		alarm(0);
	}
}


void handle_child(session_t *sess)
{
	ftp_reply(sess, FTP_GREET, "(miniftpd v1.0)");
	int ret;
	int i;
	while(1)
	{
		memset(sess->cmdline, 0, MAX_COMMAND_LINE);
		memset(sess->cmd, 0, MAX_COMMAND);
		memset(sess->arg, 0, MAX_ARG);

		//安装控制连接空闲断开闹钟信号
		start_cmdio_alarm();

		ret = readline(sess->ctrl_fd, sess->cmdline, MAX_COMMAND_LINE);
		if(ret == -1)
			ERR_EXIT("readline");
		else if(ret == 0)
			exit(EXIT_SUCCESS);
		
		str_trim_crlf(sess->cmdline);
		str_split(sess->cmdline, sess->cmd, sess->arg, ' ');

		//读取客户端的命令，并调用相应的函数进行处理
		int table_size = sizeof(ctrl_cmds) / sizeof(ftpcmd_t);
		for(i=0; i<table_size; ++i)
		{
			if(strcmp(ctrl_cmds[i].cmd, sess->cmd) == 0)
			{
				if(ctrl_cmds[i].cmd_handler != NULL)
				{
					ctrl_cmds[i].cmd_handler(sess);
				}
				else
					ftp_reply(sess, FTP_COMMANDNOTIMPL, "Unimplement command.");
				break;
			}
		}

		if(i >= table_size)
		{
			ftp_reply(sess, FTP_BADCMD, "Unknown command.");
		}
	}
}

void ftp_reply(session_t *sess, int code, const char *text)
{
	char buf[1024] = {0};
	sprintf(buf, "%d %s\r\n",code, text);
	send(sess->ctrl_fd, buf, strlen(buf), 0);
}

void do_user(session_t *sess)
{
	struct passwd *pwd = getpwnam(sess->arg);
	if(pwd == NULL)
	{
		ftp_reply(sess, FTP_LOGINERR, "0 Login incorrect.");
		return;
	}
	sess->uid = pwd->pw_uid;
	ftp_reply(sess, FTP_GIVEPWORD, "Please specify the password.");
}

void do_pass(session_t *sess)
{
	struct passwd *pwd = getpwuid(sess->uid);
	if(pwd == NULL)
	{
		ftp_reply(sess, FTP_LOGINERR, "Login incorrect.");
		return;
	}

	struct spwd *spd = getspnam(pwd->pw_name);
	if(spd == NULL)
	{
		ftp_reply(sess, FTP_LOGINERR, "Login incorrect.");
		return;
	}
	
	char *encrypted_pwd = crypt(sess->arg, spd->sp_pwdp);
	if(strcmp(encrypted_pwd, spd->sp_pwdp) != 0)
	{
		ftp_reply(sess, FTP_LOGINERR, "Login incorrect.");
		return;
	}

	setegid(pwd->pw_gid);
	seteuid(pwd->pw_uid);
	chdir(pwd->pw_dir);
	ftp_reply(sess, FTP_LOGINOK, "Login successful.");
}


void do_feat(session_t *sess)
{
	send(sess->ctrl_fd, "211-Features:\r\n", strlen("211-Features:\r\n"), 0);
	send(sess->ctrl_fd, "EPRT\r\n", strlen("EPRT\r\n"), 0);
	send(sess->ctrl_fd, "EPSV\r\n", strlen("EPSV\r\n"), 0);
	send(sess->ctrl_fd, "MDTM\r\n", strlen("MDTM\r\n"), 0);
	send(sess->ctrl_fd, "PASV\r\n", strlen("PASV\r\n"), 0);
	send(sess->ctrl_fd, "REST STREAM\r\n", strlen("REST STREAM\r\n"), 0);
	send(sess->ctrl_fd, "SIZE\r\n", strlen("SIZE\r\n"), 0);
	send(sess->ctrl_fd, "TVFS\r\n", strlen("TVFS\r\n"), 0);
	send(sess->ctrl_fd, "UTF8\r\n", strlen("UTF8\r\n"), 0);
	ftp_reply(sess, FTP_FEAT, "End");
}

void do_pwd(session_t *sess)
{
	char buffer[1024] = {0};
	getcwd(buffer, 1024);
	char msg[1024] = {0};
	sprintf(msg, "\"%s\"", buffer);
	ftp_reply(sess, FTP_PWDOK, msg);
}

void do_type(session_t *sess)
{
	if(strcmp(sess->arg, "A") == 0)
	{
		sess->is_ascii = 1;
		ftp_reply(sess, FTP_TYPEOK, "Switching to ASCII mode.");
	}
	else if(strcmp(sess->arg, "I") == 0)
	{
		sess->is_ascii = 0;
		ftp_reply(sess, FTP_TYPEOK, "Switching to Binary mode.");
	}
	else
		ftp_reply(sess, FTP_BADCMD, "Unrecognised TYPE command.");
}

void do_port(session_t *sess)
{
	unsigned int v[6];
	sscanf(sess->arg, "%u,%u,%u,%u,%u,%u", &v[0], &v[1], &v[2], &v[3], &v[4], &v[5]);

	sess->port_addr = (struct sockaddr_in*)malloc(sizeof(struct sockaddr_in));
	unsigned char *p = (unsigned char*)&sess->port_addr->sin_port;
	p[0] = v[4];
	p[1] = v[5];

	p = (unsigned char*)&sess->port_addr->sin_addr;
	p[0] = v[0];
	p[1] = v[1];
	p[2] = v[2];
	p[3] = v[3];

	sess->port_addr->sin_family = AF_INET;
	ftp_reply(sess, FTP_PORTOK, "PORT command successful. Consider using PASV.");
}

void do_pasv(session_t *sess)
{
	priv_sock_send_cmd(sess->child_fd, PRIV_SOCK_PASV_LISTEN);
	unsigned short port = (unsigned short)priv_sock_get_int(sess->child_fd);

	//先暂时写死
	char ip[16] = "192.168.232.10";
	//char ip[16] = {0};
	//getlocalip(ip);
	int v[4];
	sscanf(ip, "%u.%u.%u.%u", &v[0], &v[1], &v[2], &v[3]);

	char text[1024] = {0};
	sprintf(text, "Entering Passive Mode (%u,%u,%u,%u,%u,%u).", v[0], v[1], v[2], v[3], port>>8, port&0x00ff);
	ftp_reply(sess, FTP_PASVOK, text);
}


//数据连接获取
int port_active(session_t *sess)
{
	if(sess->port_addr)
	{
		if(pasv_active(sess))
		{
			fprintf(stderr, "both port an pasv are active"); 
			exit(EXIT_FAILURE);
		}
		return 1;
	}
	return 0;
}
int pasv_active(session_t *sess)
{
	if(sess->pasv_listen_fd != -1) //
	{
		if(port_active(sess))
		{
			fprintf(stderr, "both port an pasv are active"); 
			exit(EXIT_FAILURE);
		}
		return 1;
	}
	return 0;
}

int get_port_fd(session_t *sess)
{
	priv_sock_send_cmd(sess->child_fd, PRIV_SOCK_GET_DATA_SOCK);

	unsigned short port = ntohs(sess->port_addr->sin_port);
	char *ip = inet_ntoa(sess->port_addr->sin_addr);
	priv_sock_send_int(sess->child_fd, (int)port);
	priv_sock_send_buf(sess->child_fd, ip, strlen(ip));

	int ret = 1;

	char res = priv_sock_get_result(sess->child_fd);
	if(res == PRIV_SOCK_RESULT_OK)
	{
		sess->data_fd = priv_sock_recv_fd(sess->child_fd);
	}
	else if(res == PRIV_SOCK_RESULT_BAD)
	{
		ret = 0;
	}

	return ret;
}

int get_pasv_fd(session_t *sess)
{
	int ret = 1;
	priv_sock_send_cmd(sess->child_fd, PRIV_SOCK_PASV_ACCEPT);
	char res = priv_sock_get_result(sess->child_fd);
	
	if(res == PRIV_SOCK_RESULT_BAD)
	{
		ret = 0;
	}
	else if(res == PRIV_SOCK_RESULT_OK)
	{
		sess->data_fd = priv_sock_recv_fd(sess->child_fd);
	}
	return ret;
}

int get_transfer_fd(session_t *sess)
{
	if(!port_active(sess) && !pasv_active(sess))
	{
		ftp_reply(sess, FTP_BADSENDCONN, "Use PORT or PASV first.");
		return 0;
	}

	int ret = 1;
	//port
	if(port_active(sess))
	{	
		if(!get_port_fd(sess))
			ret = 0;
	}

	//pasv
	if(pasv_active(sess))
	{
		if(!get_pasv_fd(sess))
			ret = 0;
	}

	if(sess->port_addr)
	{
		free(sess->port_addr);
		sess->port_addr = NULL;
	}

	//安装数据连接空闲断开信号
	if(ret)
		start_data_alarm();

	sess->data_process = 1;

	return ret;
}

int list_common(session_t *sess, int detail)
{
	DIR *dir = opendir(".");
	if (dir == NULL) 
	{
		return 0;
	}

	struct dirent *dt;
	struct stat sbuf;
	while ((dt = readdir(dir)) != NULL) 
	{
		if (lstat(dt->d_name, &sbuf) < 0) 
		{
			continue;
		}
        if (dt->d_name[0] == '.') 
		{
			continue;
        }

		char buf[1024] = {0};
		if (detail) 
		{
			const char *perms = statbuf_get_perms(&sbuf);

			int off = 0;
			off += sprintf(buf, "%s ", perms);
			off += sprintf(buf + off, " %3d %-8d %-8d ", (int)sbuf.st_nlink, sbuf.st_uid, sbuf.st_gid);
			off += sprintf(buf + off, "%8lu ", (unsigned long)sbuf.st_size);

			const char *datebuf = statbuf_get_date(&sbuf);
			off += sprintf(buf + off, "%s ", datebuf);
			if (S_ISLNK(sbuf.st_mode)) 
			{
				char tmp[1024] = {0};
				readlink(dt->d_name, tmp, sizeof(tmp));
				off += sprintf(buf + off, "%s -> %s\r\n", dt->d_name, tmp);
			} 
			else 
			{
				off += sprintf(buf + off, "%s\r\n", dt->d_name);
			}
		}
		else 
		{
			sprintf(buf, "%s\r\n", dt->d_name);
		}
		
		send(sess->data_fd, buf, strlen(buf), 0);
	}

	closedir(dir);
	return 1;
}

void do_list(session_t *sess)
{
	if(get_transfer_fd(sess) == 0)
		return;

	ftp_reply(sess, FTP_DATACONN, "Here comes the directory listing.");

	//显示列表
	list_common(sess, 1);

	close(sess->data_fd);
	sess->data_fd = -1;
	ftp_reply(sess, FTP_TRANSFEROK, "Directory send OK.");
}

void do_cwd(session_t *sess)
{
	if(chdir(sess->arg) < 0)
	{
		ftp_reply(sess, FTP_NOPERM, "Failed to change directory.");
		return;
	}
	ftp_reply(sess, FTP_CWDOK, "Directory successfully changed.");
}

void do_cdup(session_t *sess)
{
	if(chdir("..") < 0)
	{
		ftp_reply(sess, FTP_NOPERM, "Failed to change directory.");
		return;
	}
	ftp_reply(sess, FTP_CWDOK, "Directory successfully changed.");
}

void do_mkd(session_t *sess)
{
	if(mkdir(sess->arg, 0777) < 0)
	{
		ftp_reply(sess, FTP_NOPERM, "Create directory operation failed.");
		return;
	}

	char text[1024] = {0};
	sprintf(text, "\"%s\" create", sess->arg);
	ftp_reply(sess, FTP_MKDIROK, text);
}
void do_dele(session_t *sess)
{
	if(unlink(sess->arg) < 0)
	{
		//550 Delete operation failed.
		ftp_reply(sess, FTP_NOPERM, "Delete operation failed.");
		return;
	}

	//250 Delete operation successful.
	ftp_reply(sess, FTP_DELEOK, "Delete operation successful.");
}
void do_rmd(session_t *sess)
{
	if(rmdir(sess->arg) < 0)
	{
		ftp_reply(sess, FTP_FILEFAIL, "Remove directory operation failed.");
		return;
	}
	//250 Remove directory operation successful.
	ftp_reply(sess, FTP_RMDIROK, "Remove directory operation successful.");
}
void do_size(session_t *sess)
{
	struct stat sbuf;
	if(stat(sess->arg, &sbuf) < 0)
	{
		ftp_reply(sess, FTP_FILEFAIL, "SIZE operation failed.");
		return;
	}

	if(!S_ISREG(sbuf.st_mode))
	{
		ftp_reply(sess, FTP_FILEFAIL, "Could not get file size.");
		return;
	}

	char text[1024] = {0};
	sprintf(text, "%lld", (long long)sbuf.st_size);
	ftp_reply(sess, FTP_SIZEOK, text);
}

void do_rnfr(session_t *sess)
{
	sess->rnfr_name = (char*)malloc(strlen(sess->arg) + 1);
	memset(sess->rnfr_name, 0, strlen(sess->arg)+1);
	strcpy(sess->rnfr_name, sess->arg);
	// 350 Ready for RNTO.
	ftp_reply(sess, FTP_RNFROK, "Ready for RNTO.");
}
void do_rnto(session_t *sess)
{
	if(sess->rnfr_name == NULL)
	{
		ftp_reply(sess, FTP_NEEDRNFR, "RNFR required first.");
		return;
	}
	if(rename(sess->rnfr_name, sess->arg) < 0)
	{
		ftp_reply(sess, FTP_NOPERM, "Rename failed.");
		return;
	}

	free(sess->rnfr_name);
	sess->rnfr_name = NULL;
	//250 Rename successful.
	ftp_reply(sess, FTP_RENAMEOK, "Rename successful.");
}

//限速
void limit_rate(session_t *sess, int bytes_transfered, int is_upload)
{
	long curr_sec = get_time_sec();
	long curr_usec = get_time_usec();

	double elapsed;
	elapsed = (double)(curr_sec - sess->bw_transfer_start_sec);
	elapsed += (double)(curr_usec - sess->bw_transfer_start_usec) / (double)1000000;
	
	unsigned int bw_rate = (unsigned int)((double)bytes_transfered / elapsed);

	double rate_ratio;
	if (is_upload) 
	{
		if (bw_rate <= sess->bw_upload_rate_max)
		{
			// 不需要限速
			sess->bw_transfer_start_sec = curr_sec;
			sess->bw_transfer_start_usec = curr_usec;
			return;
		}
		rate_ratio = bw_rate / sess->bw_upload_rate_max;
	} 
	else 
	{
		if (bw_rate <= sess->bw_download_rate_max) 
		{
			// 不需要限速
			sess->bw_transfer_start_sec = curr_sec;
			sess->bw_transfer_start_usec = curr_usec;
			return;
		}

		rate_ratio = bw_rate / sess->bw_download_rate_max;
	}

	// 睡眠时间 = (当前传输速度 / 最大传输速度 – 1) * 当前传输时间;
	double pause_time;
	pause_time = (rate_ratio - (double)1) * elapsed;

	nano_sleep(pause_time);

	sess->bw_transfer_start_sec = get_time_sec();
	sess->bw_transfer_start_usec = get_time_usec();
}

//断点
void do_rest(session_t *sess)
{
	sess->restart_pos = (long)atoi(sess->arg);

	char text[1024] = {0};
	sprintf(text, "Restart position accepted (%ld).", sess->restart_pos);
	ftp_reply(sess, FTP_RESTOK, text);
}

//上传
void do_stor(session_t *sess)
{
	if(get_transfer_fd(sess) == 0)
		return;
	int fd = open(sess->arg, O_CREAT|O_WRONLY, 0755);
	if(fd == -1)
	{
		ftp_reply(sess, FTP_FILEFAIL, "Failed to open file.");
		return;
	}

	int offset = sess->restart_pos;
	sess->restart_pos = 0;

	struct stat sbuf;
	fstat(fd, &sbuf);
	if(!S_ISREG(sbuf.st_mode))
	{
		ftp_reply(sess, FTP_FILEFAIL, "Failed to open file.");
		return;
	}

	//150 Ok to send data.
	ftp_reply(sess, FTP_DATACONN, "Ok to send data.");

	if(lseek(fd, offset, SEEK_SET) < 0)
	{
		ftp_reply(sess, FTP_UPLOADFAIL, "Could not create file.");
		return;
	}

	sess->bw_transfer_start_sec = get_time_sec();
	sess->bw_transfer_start_usec = get_time_usec();

	char buf[1024] = {0};
	int ret;
	int flag;
	while(1)
	{
		ret = read(sess->data_fd, buf, sizeof(buf));
		if(ret == -1)
		{
			flag = 2;
			break;
		}
		else if(ret == 0)
		{
			flag = 0;
			break;
		}
		if(sess->bw_upload_rate_max != 0)
			limit_rate(sess, ret, 1);

		if(write(fd, buf, ret) != ret)
		{
			flag = 1;
			break;
		}
	}


	close(fd);
	close(sess->data_fd);
	sess->data_fd = -1;

	if(flag == 0)
	{
		ftp_reply(sess, FTP_TRANSFEROK, "Transfer complete.");
	}
	else if(flag == 1)
	{
		ftp_reply(sess, FTP_BADSENDNET, "Failure writting to network stream.");
	}
	else if(flag == 2)
	{
		ftp_reply(sess, FTP_BADSENDFILE, "Failure reading from local file.");
	}
}

//下载
void do_retr(session_t *sess)
{
	if(get_transfer_fd(sess) == 0)
		return;

	int offset = sess->restart_pos;
	sess->restart_pos = 0;

	//打开文件
	int fd = open(sess->arg, O_RDONLY);
	if(fd == -1)
	{
		ftp_reply(sess, FTP_FILEFAIL, "Failed to open file.");
		return;
	}


	struct stat sbuf;
	fstat(fd, &sbuf);
	if(!S_ISREG(sbuf.st_mode))
	{
		ftp_reply(sess, FTP_FILEFAIL, "Failed to open file.");
		return;
	}

	char text[1024] = {0};
	if(sess->is_ascii)
	{
		sprintf(text, "Opening ASCII mode data connection for %s (%lld bytes).",sess->arg, (long long)sbuf.st_size);
	}
	else
	{
		sprintf(text, "Opening BINARY mode data connection for %s (%lld bytes).",sess->arg, (long long)sbuf.st_size);
	}
	ftp_reply(sess, FTP_DATACONN, text);

	//下载文件
	char buf[1024] = {0};
	int ret = 0;
	int read_total_bytes = sbuf.st_size;
	int read_count;
	int flag;

	if(offset > read_total_bytes)
	{
		ftp_reply(sess, FTP_TRANSFEROK, "Transfer complete.");
		return;
	}
	
	read_total_bytes -= offset;
	if(lseek(fd, offset, SEEK_SET) < 0)
	{
		ftp_reply(sess, FTP_UPLOADFAIL, "Could not create file.");
		return;
	}
	
	sess->bw_transfer_start_sec = get_time_sec();
	sess->bw_transfer_start_usec = get_time_usec();

	while(read_total_bytes > 0)
	{
		read_count = read_total_bytes > 1024 ? 1024 : read_total_bytes;
		ret = read(fd, buf, read_count);
		if(ret == 0)
		{
			flag = 0; //OK
			break;
		}
		else if(ret != read_count)
		{
			flag = 1;
			break;
		}
		else if(ret == -1)
		{
			flag = 2;
			break;
		}
		
		if(sess->bw_download_rate_max != 0)
			limit_rate(sess, read_count, 0);

		if(write(sess->data_fd, buf, ret) != ret)
		{
			flag = 1;
			break;
		}
		read_total_bytes -= read_count;
	}
	
	close(sess->data_fd);
	sess->data_fd = -1;
	close(fd);
	if(flag == 0)
	{
		ftp_reply(sess, FTP_TRANSFEROK, "Transfer complete.");
	}
	else if(flag == 1)
	{
		ftp_reply(sess, FTP_BADSENDNET, "Failure writting to network stream.");
	}
	else if(flag == 2)
	{
		ftp_reply(sess, FTP_BADSENDFILE, "Failure reading from local file.");
	}
}