#ifndef _STR_H_
#define _STR_H_

#include"common.h"

void str_trim_crlf(char *str);
void str_split(const char *str , char *left, char *right, char c);
int str_all_space(const char *str);
void str_upper(char *str);

#endif