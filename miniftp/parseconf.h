#ifndef _PARSE_CONF_H_
#define _PARSE_CONF_H_

#include"common.h"
#include"tunable.h"
#include"str.h"

void parseconf_load_file(const char *path);
void parseconf_load_setting(const char *setting);

#endif