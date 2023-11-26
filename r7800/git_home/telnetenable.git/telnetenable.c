/*
  This program is a re-implementation of the telnet console enabler utility
  for use with Netgear wireless routers.
  
  The original Netgear Windows binary version of this tool is available here:
  http://www.netgear.co.kr/Support/Product/FileInfo.asp?IDXNo=155
  
  Per DMCA 17 U.S.C. §1201(f)(1)-(2), the original Netgear executable was
  reverse engineered to enable interoperability with other operating systems
  not supported by the original windows-only tool (MacOS, Linux, etc).

  Currently his program implements the only the signing and encryption parts
  of Netgear telnet-enable algorithm, it does not provide the network socket
  support, but can trivially be used with 'netcat' or other tools capable of
  sending the output of this program to telnet port 23 on the router.
  

	Netgear Router - Console Telnet Enable Utility 
	Release 0.1 : 25th June 2006
	Copyright (C) 2006, yoshac @ member.fsf.org

	This program is free software; you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation; either version 2 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License along
	with this program; if not, write to the Free Software Foundation, Inc.,
	51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.


  The RSA MD5 and Blowfish implementations are provided under LGPL from
  http://www.opentom.org/Mkttimage 
 
  Added a socket layer by haiyue @ Delta Networks Inc. 2008-02-25
  Hope yoshac NOT mind the stupid modification :)
*/
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/select.h>
#include <fcntl.h>
#include <errno.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "md5.h"
#include "blowfish.h"

/*
 * dni_system
 * output: the file that the output will be redirected to, or fill with NULL if you don't want to redirect the output
 * mode: the mode that you want to redirect. R_NORMAL = 'cmd > output', R_STDERR = 'cmd > output 2>&1', R_APPEND = 'cmd >> output', R_OUTPUT = 'cmd 1> output 2>err'
 * cmd: the absolute path of the command (executable binary or script)
 * ...: the argument strings passed to the command, must end with NULL
 * example 1: dni_safe_system(NULL, NULL, R_NORMAL, "/bin/ls", NULL);
 * example 2: dni_safe_system("/tmp/result", NULL, R_NORMAL, "/bin/ls", "-l", NULL);
 */
typedef void (*sighandler_t)(int);
#include <stdarg.h>
#include <signal.h>
#include <sys/wait.h>
extern char **__environ;
#define MAX_SYSTEM_ARG 100
#ifndef R_NORMAL
#define R_NORMAL 0
#define R_STDERR 0x01
#define R_APPEND 0x02
#define R_OUTPUT 0x03
#endif

int dni_safe_system(const char *output, const char *output2, unsigned char mode, const char *cmd, ...)
{
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
		char *argv[MAX_SYSTEM_ARG] = {NULL};
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
			if (i < MAX_SYSTEM_ARG)
				argv[i++] = p;
			else {
				printf("warning: drop some argv!\n");
				break;
			}
		}
		va_end(args);

		if (output) {
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
		if (output2) {
			if (!(mode & R_APPEND))
				unlink(output2);
			if ((fd = open(output2, O_WRONLY | O_CREAT | ((mode & R_APPEND) ? O_APPEND : 0), 0666)) < 0) {
				printf("can not open %s %s\n", output, strerror(errno));
				_exit(127);
			}
			if (mode & R_OUTPUT)
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

struct PAYLOAD
{
	char signature[0x10];
	char mac[0x10];
	char username[0x10];
	char password[0x88];
	char reserved[0x40];
};

#define __BIG_ENDIAN__	1

#define LAN_IFNAME	"br0"

#define TELNET_CMD	"/usr/sbin/utelnetd -d -i " LAN_IFNAME

#define REGION_FILE     "/tmp/firmware_region"
#define PASSWORD_FILE	"/tmp/uhttp_key_telnet" 
#define LANGUAGE_FILE	"/tmp/gui_language_telnet"

/* the content of file is stored in static array */
static char *cat_file(char *name)
{
        int i;
        FILE *fp;
        static char buf[512];

        buf[0] = '\0';

        fp = fopen(name, "r");
        if (fp == NULL)
                return buf;
        fgets(buf, sizeof(buf), fp);
        fclose(fp);

        i = 0;
        while (buf[i] != '\0' && buf[i] != '\r' && buf[i] != '\n')
                i++;
        buf[i] = '\0';

        return buf;
}

/*******************************************************************/
static void ether_etoa(char *p, unsigned char *e)
{	
	int i;
	static const char hex[] = "0123456789ABCDEF";

	for (i = 0; i < 6; i++) {
		p[2*i] = hex[e[i] >> 4];
		p[2*i + 1] = hex[e[i] & 0x0F];
	}

	p[2*i] = '\0';
}

static void get_mac(char *p, char *ifname)
{
	int s;
	struct ifreq ifr;
	
	s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (s < 0) {
err:		printf("Can't get the MAC address of %s.\n", ifname);
		exit(-1);
	}
 	
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	if (ioctl(s, SIOCGIFHWADDR, &ifr) == 0)
		ether_etoa(p, (unsigned char *)ifr.ifr_hwaddr.sa_data);
	else
		goto err;
	close(s);
}

static int open_telnet(char *ifname)
{
	int fd, on = 1;
	struct ifreq ifr;
	struct sockaddr_in sa;
	
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return -1;

	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
		close(fd);
		return -1;
	}
	
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(23);
	sa.sin_addr = ((struct sockaddr_in *)(&ifr.ifr_addr))->sin_addr;
	
	if (bind(fd, (struct sockaddr *) &sa, sizeof(sa)) < 0) {
		close(fd);
		return -1;
	}

	return fd;
}

/****************************************************************/

int GetOutputLength(unsigned long lInputLong)
{
	unsigned long lVal = lInputLong % 8;

	if (lVal!=0)
		return lInputLong+8-lVal;
	else
		return lInputLong;
}

#define GET32U(p, x) do { \
			x = p[3]; \
			x = (x << 8) |p[2]; \
			x = (x << 8) |p[1]; \
			x = (x << 8) |p[0]; \
		} while(0)
	
#define PUT32U(p, x) do { \
			p[0] = (x) & 0xFF; \
			p[1] = (x >> 8) & 0xFF; \
			p[2] = (x >> 16) & 0xFF; \
			p[3] = (x >> 24) & 0xFF; \
		} while(0)
	
int EncodeString(void *ctx, char *pInput,char *pOutput, int lSize)
{
	int lCount = 0;
	int lOutSize = 0;

#if __BIG_ENDIAN__
	unsigned char *pi = (unsigned char *)pInput;
	unsigned char *po = (unsigned char *)pOutput;
#else
	int i = 0;
#endif

	lOutSize = GetOutputLength(lSize);
	lCount=0;
	while (lCount<lOutSize)
	{
	#if __BIG_ENDIAN__	
		uint32 xl, xr;

		GET32U(pi, xl); pi +=4;
		GET32U(pi, xr); pi +=4;
		Blowfish_Encrypt(ctx, &xl, &xr);
		PUT32U(po, xl); po += 4;
		PUT32U(po, xr); po += 4;
		
		lCount += 8;
	#else
		char *pi=pInput;
		char *po=pOutput;
		for (i=0; i<8; i++)
			*po++=*pi++;
		Blowfish_Encrypt(ctx, (uint32 *)pOutput, (uint32 *)(pOutput+4));
		pInput+=8;
		pOutput+=8;
		lCount+=8;
	#endif
	}

	return lCount;
}

int fill_payload(char *p)
{
	int secret_len = 0;
	int encoded_len = 0;
	MD5_CTX MD;
	BLOWFISH_CTX BF;
	struct PAYLOAD payload;
	char *username = "admin";
	char pwd[128] = {0};
	char mac[0x10] = {0}, MD5_key[0x11] = {0};
	char secret_key[0x100] = {0};
	FILE *fp = NULL;

	fp = fopen(PASSWORD_FILE, "r");
	if (fp != NULL) {
		fgets(pwd, sizeof(pwd), fp);
		fclose(fp);
	}

	get_mac(mac, LAN_IFNAME);

	memset(&payload, 0, sizeof(payload));
	strncpy(payload.mac, mac, sizeof(payload.mac));
	strncpy(payload.username, username, sizeof(payload.username));
	strncpy(payload.password, pwd, sizeof(payload.password));

	MD5Init(&MD);
	MD5Update(&MD, (unsigned char *)payload.mac, 0x70);
	MD5Final((unsigned char *)MD5_key, &MD);

#if 1
	memcpy(payload.signature, MD5_key, 0x10);
#else
	MD5_key[0x10] = '\0'; /* ?? */
	strcpy(payload.signature, MD5_key);
	strcat(payload.signature, mac);
#endif

	secret_len = snprintf(secret_key, sizeof(secret_key), "AMBIT_TELNET_ENABLE+%s", pwd);
	Blowfish_Init(&BF, (unsigned char *)secret_key, secret_len);	
	encoded_len = EncodeString(&BF, (char*)&payload, p, sizeof(payload));

	return encoded_len;
}

int main(int argc, char * argv[])
{
	int fd;
	socklen_t slen;
	struct sockaddr_in from;
	fd_set readable;
	int telnet_enabled = 0;
	int r = 0, datasize = 0;
	char rbuf[512] = {0}, output_buf[512] = {0};
	char ack[] = "ACK";

	fd = open_telnet(LAN_IFNAME);
	if (fd < 0) {
		printf("Can't open the socket!\n");
		return -1;
	}

	daemon(1,1);
	printf("The telnetenable is running ...\n");

	for (;;) {
		FD_ZERO(&readable);
		FD_SET(fd, &readable);

		if (select(fd + 1, &readable, NULL, NULL, NULL) < 1)
			continue;

		slen = sizeof(struct sockaddr_in);
		r = recvfrom(fd, rbuf, sizeof(rbuf), 0, (struct sockaddr *)&from, &slen);
		if (r < 1)
			continue;
		
		dni_safe_system(NULL, NULL, R_NORMAL, "/usr/sbin/telnet_update.sh", NULL);
		datasize = fill_payload(output_buf);
		if (r == datasize && memcmp(rbuf, output_buf, r) == 0) {
			/* maybe it's better to judge whether utelnetd is running in real time here */
			if (telnet_enabled == 0) {
				printf("The telnet server is enabled now!!!\n");
				dni_safe_system(NULL, NULL, R_NORMAL, "/usr/sbin/utelnetd", "-d", "-i", LAN_IFNAME, NULL);
				telnet_enabled = 1;
			}
			sendto(fd, ack, 3, 0, (struct sockaddr *)&from, slen);
		}
		remove(PASSWORD_FILE);
		remove(LANGUAGE_FILE);
	}
	close(fd);	
	return 0;
}

