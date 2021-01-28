#include"sysutil.h"

int tcp_client()
{
	int sock;
	if ((sock = socket(PF_INET, SOCK_STREAM, 0)) < 0)
		ERR_EXIT("tcp_client");
	return sock;
}

int tcp_server(const char *host, unsigned short port)
{
	int listenfd;
	if ((listenfd = socket(PF_INET, SOCK_STREAM, 0)) < 0)
		ERR_EXIT("tcp_server");

	struct sockaddr_in servaddr;
	memset(&servaddr, 0, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = inet_addr(host);
	servaddr.sin_port = htons(port);

	
	int on = 1;
	if ((setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, (const char*)&on, sizeof(on))) < 0)
		ERR_EXIT("setsockopt");

	if (bind(listenfd, (struct sockaddr*)&servaddr, sizeof(servaddr)) < 0)
		ERR_EXIT("bind");

	if (listen(listenfd, SOMAXCONN) < 0)
		ERR_EXIT("listen");

	return listenfd;
}

ssize_t readn(int fd, void *buf, size_t count)
{
	size_t nleft = count;
	ssize_t nread;
	char *bufp = (char*)buf;

	while (nleft > 0) 
	{
		if ((nread = read(fd, bufp, nleft)) < 0) 
		{
			if (errno == EINTR)
				continue;
			return -1;
		}
		else if (nread == 0)
			return count - nleft;

		bufp += nread;
		nleft -= nread;
	}
	return count;
}

size_t recv_peek(int sockfd, void *buf, size_t len)
{
	while (1) 
	{
		int ret = recv(sockfd, buf, len, MSG_PEEK);
		if (ret == -1 && errno == EINTR)
			continue;
		return ret;
	}
}

size_t readline(int sockfd, void *buf, size_t maxline)
{
	int ret;
	int nread;
	char *bufp = buf;
	int nleft = maxline;
	while (1) 
	{
		ret = recv_peek(sockfd, bufp, nleft);
		if (ret < 0)
			return ret;
		else if (ret == 0)
			return ret;

		nread = ret;
		int i;
		for (i=0; i<nread; i++) 
		{
			if (bufp[i] == '\n') 
			{
				ret = readn(sockfd, bufp, i+1);
				if (ret != i+1)
					exit(EXIT_FAILURE);

				return ret;
			}
		}

		if (nread > nleft)
			exit(EXIT_FAILURE);

		nleft -= nread;
		ret = readn(sockfd, bufp, nread);
		if (ret != nread)
			exit(EXIT_FAILURE);

		bufp += nread;
	}
	return -1;
}

const char* statbuf_get_perms(struct stat *sbuf)
{
	static char perms[] = "----------";
	perms[0] = '?';

	mode_t mode = sbuf->st_mode;
	switch (mode & S_IFMT) {
	case S_IFREG:
		perms[0] = '-';
		break;
	case S_IFDIR:
		perms[0] = 'd';
		break;
	case S_IFLNK:
		perms[0] = 'l';
		break;
	case S_IFIFO:
		perms[0] = 'p';
		break;
	case S_IFSOCK:
		perms[0] = 's';
		break;
	case S_IFCHR:
		perms[0] = 'c';
		break;
	case S_IFBLK:
		perms[0] = 'b';
		break;
	}

	if (mode & S_IRUSR) {
		perms[1] = 'r';
	}
	if (mode & S_IWUSR) {
		perms[2] = 'w';
	}
	if (mode & S_IXUSR) {
		perms[3] = 'x';
	}
	if (mode & S_IRGRP) {
		perms[4] = 'r';
	}
	if (mode & S_IWGRP) {
		perms[5] = 'w';
	}
	if (mode & S_IXGRP) {
		perms[6] = 'x';
	}
	if (mode & S_IROTH) {
		perms[7] = 'r';
	}
	if (mode & S_IWOTH) {
		perms[8] = 'w';
	}
	if (mode & S_IXOTH) {
		perms[9] = 'x';
	}
	if (mode & S_ISUID) {
		perms[3] = (perms[3] == 'x') ? 's' : 'S';
	}
	if (mode & S_ISGID) {
		perms[6] = (perms[6] == 'x') ? 's' : 'S';
	}
	if (mode & S_ISVTX) {
		perms[9] = (perms[9] == 'x') ? 't' : 'T';
	}

	return perms;
}

const char* statbuf_get_date(struct stat *sbuf)
{
	static char datebuf[64] = {0};
	const char *p_date_format = "%b %e %H:%M";
	struct timeval tv;
	gettimeofday(&tv, NULL);
	time_t local_time = tv.tv_sec;
	if (sbuf->st_mtime > local_time || (local_time - sbuf->st_mtime) > 60*60*24*182) 
	{
		p_date_format = "%b %e  %Y";
	}

	struct tm* p_tm = localtime(&local_time);
	strftime(datebuf, sizeof(datebuf), p_date_format, p_tm);

	return datebuf;
}

void send_fd(int sock_fd, int fd)
{
	int ret;
	struct msghdr msg;
	struct cmsghdr *p_cmsg;
	struct iovec vec;
	char cmsgbuf[CMSG_SPACE(sizeof(fd))];
	int *p_fds;
	char sendchar = 0;
	msg.msg_control = cmsgbuf;
	msg.msg_controllen = sizeof(cmsgbuf);
	p_cmsg = CMSG_FIRSTHDR(&msg);
	p_cmsg->cmsg_level = SOL_SOCKET;
	p_cmsg->cmsg_type = SCM_RIGHTS;
	p_cmsg->cmsg_len = CMSG_LEN(sizeof(fd));
	p_fds = (int*)CMSG_DATA(p_cmsg);
	*p_fds = fd;

	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_iov = &vec;
	msg.msg_iovlen = 1;
	msg.msg_flags = 0;

	vec.iov_base = &sendchar;
	vec.iov_len = sizeof(sendchar);
	ret = sendmsg(sock_fd, &msg, 0);
	if (ret != 1)
		ERR_EXIT("sendmsg");
}

int recv_fd(const int sock_fd)
{
	int ret;
	struct msghdr msg;
	char recvchar;
	struct iovec vec;
	int recv_fd;
	char cmsgbuf[CMSG_SPACE(sizeof(recv_fd))];
	struct cmsghdr *p_cmsg;
	int *p_fd;
	vec.iov_base = &recvchar;
	vec.iov_len = sizeof(recvchar);
	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_iov = &vec;
	msg.msg_iovlen = 1;
	msg.msg_control = cmsgbuf;
	msg.msg_controllen = sizeof(cmsgbuf);
	msg.msg_flags = 0;

	p_fd = (int*)CMSG_DATA(CMSG_FIRSTHDR(&msg));
	*p_fd = -1;  
	ret = recvmsg(sock_fd, &msg, 0);
	if (ret != 1)
		ERR_EXIT("recvmsg");

	p_cmsg = CMSG_FIRSTHDR(&msg);
	if (p_cmsg == NULL)
		ERR_EXIT("no passed fd");


	p_fd = (int*)CMSG_DATA(p_cmsg);
	recv_fd = *p_fd;
	if (recv_fd == -1)
		ERR_EXIT("no passed fd");

	return recv_fd;
}


static struct timeval s_curr_time; 
long get_time_sec()
{
	if(gettimeofday(&s_curr_time, NULL) < 0)
	{
		ERR_EXIT("gettimeofday");
	}
	return s_curr_time.tv_sec;
}
long get_time_usec()
{
	return s_curr_time.tv_usec;
}

void nano_sleep(double seconds) //12.34
{
	time_t secs = (time_t)seconds;					// 整数部分
	double fractional = seconds - (double)secs;		// 小数部分

	struct timespec ts;
	ts.tv_sec = secs;
	ts.tv_nsec = (long)(fractional * (double)1000000000);
	
	int ret;
	do
	{
		ret = nanosleep(&ts, &ts);
	}
	while (ret == -1 && errno == EINTR);
}