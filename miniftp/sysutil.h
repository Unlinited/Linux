#ifndef _SYSUTIL_H_
#define _SYSUTIL_H_

#include"common.h"

int tcp_client();
int tcp_server(const char *host, unsigned short port);


ssize_t readn(int fd, void *buf, size_t count);
size_t recv_peek(int sockfd, void *buf, size_t len);
size_t readline(int sockfd, void *buf, size_t maxline);

//列表显示-权限-日期-获取
const char* statbuf_get_perms(struct stat *sbuf);
const char* statbuf_get_date(struct stat *sbuf);

void send_fd(int sock_fd, int fd);
int recv_fd(const int sock_fd);

long get_time_sec();
long get_time_usec();
void nano_sleep(double seconds);

#endif