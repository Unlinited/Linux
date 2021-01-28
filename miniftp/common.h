#ifndef _COMMON_H_
#define _COMMON_H_

#include<stdio.h>
#include<unistd.h>
#include<string.h>
#include<stdlib.h>
#include<ctype.h>

#include<errno.h>

#include<sys/socket.h>
#include<netinet/in.h>
#include<arpa/inet.h>

#include<netdb.h>

#include<pwd.h>
#include<shadow.h>
#include<crypt.h>

#include<sys/time.h>
#include<time.h>
#include<sys/stat.h>
#include<dirent.h>

#include<fcntl.h>

#include<linux/capability.h>
#include<sys/syscall.h>

#include<signal.h>
#include<sys/wait.h>

#define ERR_EXIT(m) \
	do{ \
	perror(m);\
	exit(EXIT_FAILURE);\
	}while(0)


#define MAX_COMMAND_LINE 1024
#define MAX_COMMAND      32
#define MAX_ARG          1024

#endif /* _COMMOM_H_ */