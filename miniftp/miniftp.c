#include"common.h"
#include"sysutil.h"
#include"session.h"
#include"tunable.h"
#include"parseconf.h"
#include"hash.h"
#include"ftpproto.h"


extern session_t *p_sess;
static unsigned int s_children; //连接数

//连接数限制
unsigned int hash_func(unsigned int buckets, void *key);
static hash_t *s_ip_count_hash;
static hash_t *s_pid_ip_hash;
unsigned int handle_ip_count(void *ip);
void drop_ip_count(void *ip);
void handle_sigchld(int sig);
void check_limits(session_t *sess);

int main(int argc, char *argv[])
{
	//解析配置文件
	parseconf_load_file("bitftpd.conf");

	//程序后台化
	//daemon(0,0);

	if(getuid() != 0)
	{
		printf("miniftp : must be started as root.\n");
		exit(EXIT_FAILURE);
	}

	session_t sess = 
	{
		/* 控制连接 */
		0, -1, "", "", "",       
		/* 数据连接 */
		NULL, -1, -1, 0,
		/* 限速 */
		0, 0, 0, 0,
		/* 父子进程通道 */
		-1, -1,
		/* ftp协议状态 */
		0, 0, NULL,
		/* 连接数限制 */
		0, 0
	};

	//全局回话结构session
	p_sess = &sess;

	//最大限速
	sess.bw_download_rate_max = tunable_download_max_rate; 
	sess.bw_upload_rate_max = tunable_upload_max_rate;

	int listenfd = tcp_server("192.168.232.10", 9188);

	pid_t pid;
	int conn;

	//处理子进程退出
	signal(SIGCHLD, handle_sigchld);

	struct sockaddr_in addrcli;
	socklen_t addrlen;
	while(1)
	{
		if((conn=accept(listenfd, (struct sockaddr*)&addrcli, &addrlen)) < 0)
			ERR_EXIT("accept_timeout");

		unsigned int ip = addrcli.sin_addr.s_addr;
		++s_children;
		sess.num_clients = s_children;   //更新最大连接数
		sess.num_this_ip = handle_ip_count(&ip); //更新每ip连接数

		pid = fork();
		if(pid == -1)
			ERR_EXIT("fork");

		if(pid == 0)
		{
			close(listenfd);
			sess.ctrl_fd = conn;

			//连接数限制
			check_limits(&sess);

			begin_session(&sess);
		}
		else
		{
			hash_add_entry(s_pid_ip_hash, &pid, sizeof(pid), &ip, sizeof(unsigned int));
			close(conn);
		}
	}

	close(listenfd);
	return 0;
}



unsigned int hash_func(unsigned int buckets, void *key)
{
	unsigned int *number = (unsigned int*)key;

	return (*number) % buckets;
}

unsigned int handle_ip_count(void *ip)
{
	unsigned int count;
	unsigned int *p_count = (unsigned int *)hash_lookup_entry(s_ip_count_hash, ip, sizeof(unsigned int));
	if (p_count == NULL) 
	{
		count = 1;
		hash_add_entry(s_ip_count_hash, ip, sizeof(unsigned int), &count, sizeof(unsigned int));
	}
	else 
	{
		count = *p_count;
		++count;
		*p_count = count;
	}

	return count;
}

void drop_ip_count(void *ip)
{
	unsigned int count;
	unsigned int *p_count = (unsigned int *)hash_lookup_entry(s_ip_count_hash, ip, sizeof(unsigned int));
	if (p_count == NULL) 
	{
		return;
	}

	count = *p_count;
	if (count <= 0) 
	{
		return;
	}
	--count;
	*p_count = count;

	if (count == 0) 
	{
		hash_free_entry(s_ip_count_hash, ip, sizeof(unsigned int));
	}
}


void check_limits(session_t *sess)
{
	if(tunable_max_clients > 0 && sess->num_clients > tunable_max_clients)
	{
		ftp_reply(sess, FTP_TOO_MANY_USERS, "There are too many connected users, please try later.");
		exit(EXIT_FAILURE);
	}

	if(tunable_max_per_ip > 0 && sess->num_this_ip > tunable_max_per_ip)
	{
		ftp_reply(sess, FTP_IP_LIMIT, 
			"There are too many connections from your internet address.");
		exit(EXIT_FAILURE);
	}
}

void handle_sigchld(int sig)
{
	pid_t pid;
	while ((pid = waitpid(-1, NULL, WNOHANG)) > 0)
	{
		--s_children;
		unsigned int *ip = hash_lookup_entry(s_pid_ip_hash, &pid, sizeof(pid));
		if (ip == NULL)
		{
			continue;
		}

		drop_ip_count(ip);
		hash_free_entry(s_pid_ip_hash, &pid, sizeof(pid));
	}
}
