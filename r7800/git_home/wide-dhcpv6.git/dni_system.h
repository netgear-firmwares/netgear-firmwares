#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <signal.h>
#include <unistd.h>
#include <sys/wait.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
extern char **__environ;
typedef void (*sighandler_t)(int);

extern int dni_system(const char *output, unsigned char mode, const char *cmd, ...);

extern char *str_replace_n(char *org);

/*
 * dni_system
 * output: the file that the output will be redirected to, or fill with NULL if you don't want to redirect the output
 * mode: the mode that you want to redirect. R_NORMAL = 'cmd > output', R_STDERR = 'cmd > output 2>&1', R_APPEND = 'cmd >> output'
 * cmd: the absolute path of the command (executable binary or script)
 * ...: the argument strings passed to the command, must end with NULL
 * example 1: dni_system(NULL, "/bin/ls", NULL);
 * example 2: dni_system("/tmp/result", "/bin/ls", "-l", NULL);
 */
#ifndef R_NORMAL
#define R_NORMAL 0
#define R_STDERR 0x01
#define R_APPEND 0x02
#endif

