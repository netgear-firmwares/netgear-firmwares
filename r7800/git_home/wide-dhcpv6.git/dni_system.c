/*
 * dni_system
 * output: the file that the output will be redirected to, or fill with NULL if you don't want to redirect the output
 * mode: the mode that you want to redirect. R_NORMAL = 'cmd > output', R_STDERR = 'cmd > output 2>&1', R_APPEND = 'cmd >> output'
 * cmd: the absolute path of the command (executable binary or script)
 * ...: the argument strings passed to the command, must end with NULL
 * example 1: dni_system(NULL, "/bin/ls", NULL);
 * example 2: dni_system("/tmp/result", "/bin/ls", "-l", NULL);
 */

#include "dni_system.h"

char *str_replace_n(char *org)
{
    char c,*p;
    static char buf[2048] = {0};
    
    buf[0]='\0';
    if(org == NULL)
    	return buf;
    p= buf;
    int i=0;
    while((c = org[i])!='\0' && i<sizeof(buf)){
            if(c == '\n')
	        *p++ = ' ';
	    else if (c == '\r')
	        *p++ = ' ';
	    else 
	        *p++ = c;
	i++;
    }
    *p = '\0';
    return buf;
}


int dni_system(const char *output, unsigned char mode, const char *cmd, ...)
{
#define MAX_ARG 100
	int wait_val, pid;
	sighandler_t save_quit, save_int, save_chld;
	save_quit = signal(SIGQUIT, SIG_IGN);
	save_int = signal(SIGINT, SIG_IGN);
	save_chld = signal(SIGCHLD, SIG_DFL);

	if ((pid = vfork()) < 0) {
		signal(SIGQUIT, save_quit);
		signal(SIGINT, save_int);
		signal(SIGCHLD, save_chld);
		return -1;
	}
	if (pid == 0) {
		int fd, i = 0;
		char *cmdpath;
		va_list args;
		char *argv[MAX_ARG] = {NULL};
		char *p;

		signal(SIGQUIT, SIG_DFL);
		signal(SIGINT, SIG_DFL);
		signal(SIGCHLD, SIG_DFL);

		argv[0] = cmdpath = (char *)cmd;

		va_start(args, cmd);
		for (i = 1;;) {
			p = va_arg(args, char *);
			if (p == NULL)
				break;
			if (i < MAX_ARG)
				argv[i++] = p;
			else {
				printf("warning: drop some argv!\n");
				break;
			}
		}
		va_end(args);

		if(output == NULL)
		{
			if((fd = open("/dev/null", O_RDWR)) < 0)
			{
				printf("can not open /dev/null, errno: %s", strerror(errno));
				_exit(127);
			}
			dup2(fd, STDOUT_FILENO);
			close(fd);
		}
		else
		{
			if (!(mode & R_APPEND))
				unlink(output);

			if ((fd = open(output, O_WRONLY | O_CREAT | ((mode & R_APPEND) ? O_APPEND : 0), 0666)) < 0) {
				printf("can not open %s %s\n", output, strerror(errno));
				_exit(127);
			}

			dup2(fd, STDOUT_FILENO);
			if (mode & R_STDERR)
				dup2(fd, STDERR_FILENO);
			close(fd);
		}

		execve(cmdpath, (char *const *)argv, __environ);
		_exit(127);
	}
	/* Signals are not absolutly guarenteed with vfork */
	signal(SIGQUIT, SIG_IGN);
	signal(SIGINT, SIG_IGN);

	if (wait4(pid, &wait_val, 0, 0) == -1)
		wait_val = -1;

	signal(SIGQUIT, save_quit);
	signal(SIGINT, save_int);
	signal(SIGCHLD, save_chld);
	return wait_val;
}
