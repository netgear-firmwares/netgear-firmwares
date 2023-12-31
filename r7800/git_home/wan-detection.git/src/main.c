#include "httpd.h"
#include "internet.h"

#define DEFAULT_CONFIG_FILE "/etc/detwan.conf"
static char *config_file = DEFAULT_CONFIG_FILE;

char *wan_if_name;
char *external_detwan_path;
char *host_name;
char *uk_sky_option61;
struct in6_addr from_ip6;
struct in_addr from_ip;

#ifdef Musl_Compile
/* Hex digit to integer. */
static inline int
xdtoi(c)
	register int c;
{
	if (isdigit(c))
		return c - '0';
	else if (islower(c))
		return c - 'a' + 10;
	else
		return c - 'A' + 10;
}


/*
 * Convert 's', which can have the one of the forms:
 *
 *	"xx:xx:xx:xx:xx:xx"
 *	"xx.xx.xx.xx.xx.xx"
 *	"xx-xx-xx-xx-xx-xx"
 *	"xxxx.xxxx.xxxx"
 *	"xxxxxxxxxxxx"
 *
 * (or various mixes of ':', '.', and '-') into a new
 * ethernet address.  Assumes 's' is well formed.
 */
uint8 *
pcap_ether_aton(const char *s)
{
	register uint8 *ep, *e;
	register uint8 d;

	e = ep = (uint8 *)malloc(6);
	if (e == NULL)
		return (NULL);

	while (*s) {
		if (*s == ':' || *s == '.' || *s == '-')
			s += 1;
		d = xdtoi(*s++);
		if (isxdigit((unsigned char)*s)) {
			d <<= 4;
			d |= xdtoi(*s++);
		}
		*ep++ = d;
	}

	return (e);
}
#endif

//*********** add for ap autodection********************//
int flag_apautodection = 0;
int flag_apautodection_lan=0;
int count = 1;
uint8 ap_autodection_wanaddress1[4];
uint8 ap_autodection_wanaddress2[4];
struct arpmsg
{
	/* Ethernet header */
	uint8   h_dest[6];      /* destination ether addr */
	uint8   h_source[6];    /* source ether addr */
	uint16  h_proto;                /* packet type ID field */

	/* ARP packet */
	uint16  ar_hrd; /* hardware type (must be ARPHRD_ETHER) */
	uint16  ar_pro; /* protocol type (must be ETH_P_IP) */
	uint8   ar_hln; /* hardware address length (must be 6) */
	uint8   ar_pln; /* protocol address length (must be 4) */
	uint16  ar_op;  /* ARP opcode */
	uint8   ar_sha[6];      /* sender's hardware address */
	uint8   ar_sip[4];      /* sender's IP address */
	uint8   ar_tha[6];      /* target's hardware address */
	uint8   ar_tip[4];      /* target's IP address */

	uint8   pad[18];        /* pad for min. Ethernet payload (60 bytes) */
} __attribute__ ((packed, aligned(4)));

static struct arpmsg arpreq;

void AP_autodection(uint8*);
void AP_autodection_lan(uint8*);
struct ether_addr  *ether_aton(const char *asc);
char *ether_ntoa(const struct ether_addr *addr);
int set_promisc(char *ifname);
int unset_promisc(char *ifname);
uint32_t do_detection(uint8 *dutMac, uint8 *pcMac);
int DHCP_Detection(int *bpain, uint8 *arp);
char *str_replace(char *str);

char * strReplace(char * orig)
{
	char *p;
	static char buf[128]={0};

	p = buf;
	int i = 0;
	int len = sizeof(buf);
	while( orig[i] != '\0' && i < len )
	{
		if (orig[i] == '\n' || orig[i] == '\r')
			*p++=' ';
		else
			*p++ = orig[i];
		i++;
	}
	*p = '\0';
	return buf;
}

int main(int argc, const char **argv)
{
	char **argp = (char **)&argv[1];
	uint8 *ptrmac, dutMac[6], pcMac[6];
	int ConnType,addr_ok = -1,ret= -1;
	char country[32]={0}, isp[32]={0};

	wan_if_name = NULL;
	external_detwan_path = NULL;

	while (argp < (char **)&argv[argc]) {
		if (strcasecmp(*argp, "-i") == 0)
			wan_if_name = *++argp;
		else if (strcasecmp(*argp, "-p") == 0){
			if(strstr(*++argp,":")){
				if((ret = inet_pton(AF_INET6,*argp,&from_ip6)) == 1)
					addr_ok = 6;
			}
			else{
				from_ip.s_addr = inet_addr(*argp);
				if(from_ip.s_addr != INADDR_NONE && from_ip.s_addr != INADDR_ANY)
					addr_ok = 4;
			}
		}
		else if (strcasecmp(*argp, "-d") == 0) {
#ifdef Musl_Compile
			if ((ptrmac = (uint8 *) pcap_ether_aton(*++argp)) != NULL)
#else
			if ((ptrmac = (uint8 *) ether_aton(*++argp)) != NULL)
#endif
				memcpy(dutMac, ptrmac, 6);
			else
				memset(dutMac, 0x0, 6);
			syslog(6, "[DETWAN] *External* DutMAC: %s", strReplace(*argp));
#ifdef Musl_Compile
			free(ptrmac);
#endif
		} else if (strcasecmp(*argp, "-n") == 0) {
#ifdef Musl_Compile
			if ((ptrmac = (uint8 *) pcap_ether_aton(*++argp)) != NULL)
#else
			if ((ptrmac = (uint8 *) ether_aton(*++argp)) != NULL)
#endif
				memcpy(pcMac, ptrmac, 6);
			else
				memset(pcMac, 0x0, 6);
			syslog(6, "[DETWAN] *External* PCMAC: %s", strReplace(*argp));
#ifdef Musl_Compile
			free(ptrmac);
#endif
		}
		//*********load config ********//
		else if(strcasecmp(*argp, "-config_file") == 0){
			config_file = *++argp;
		}
		//***************AP mode auto detection*********//
		else if (strcasecmp(*argp, "-k") == 0) {
			flag_apautodection=1;	
		}
		else if (strcasecmp(*argp,"-l") == 0) {
			flag_apautodection_lan=1;
		}


		argp++;
	}

	load_config(config_file);

	if (wan_if_name == NULL || addr_ok < 0) {
		printf
		    ("Usage: detwan -i (WAN interface name) -p (Managing PC's IP) -d (DutMAC) -n (PCMAC)\n");
		exit(-1);
	}

	host_name = (char *)malloc(sizeof(char) * 32);
	snprintf(host_name, sizeof(char) * 32, "%s",
		 get_conf_string("wan_hostname"));
	if(get_conf_bool("detwan_have_dsl")){
		strncpy(country, get_conf_string("dsl_wan_country"), sizeof(country)-1);
		strncpy(isp, get_conf_string("dsl_wan_isp"), sizeof(isp)-1);
		if (strcmp(country, "UK") == 0 && strcmp(isp, "Sky") == 0)
		{
			uk_sky_option61 = (char *)malloc(sizeof(char) * 128);
			snprintf(uk_sky_option61, sizeof(char) * 128, "%s", get_conf_string("dsl_wan_ether_dhcp_option61"));
		}
	}

	// add for AP mode auto detection feature
	if(1==flag_apautodection && get_conf_bool("detwan_apmode_det"))
	{		
		AP_autodection(dutMac);
		return 0;
	}
	if(1==flag_apautodection_lan && get_conf_bool("detwan_apmode_det"))
	{
		AP_autodection_lan(dutMac);
		return 0;
	}
	ConnType = do_detection(dutMac, pcMac);

	syslog(6, "[DETWAN] *External* Result of do_detection: %d", ConnType);

	return ConnType;
}

//********************AP mode auto detection feature*************//
//this function copy from net-scan
int init_arp_request(char *ifname)
{
	int s;
	struct ifreq ifr;
	struct arpmsg *arp;

	s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if(s<0)
		goto ERR;

	arp=&arpreq;
	memset(arp,0,sizeof(struct arpmsg));

	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	if (ioctl(s, SIOCGIFADDR, &ifr) != 0)
		goto ERR;
	memcpy(arp->ar_sip, &((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr, 4);

	if (ioctl(s, SIOCGIFHWADDR, &ifr) != 0)
		goto ERR;
	memset(arp->h_dest, 0xFF, 6);
	memcpy(arp->h_source, ifr.ifr_hwaddr.sa_data, 6);
	arp->h_proto = htons(ETH_P_ARP);
	arp->ar_hrd = htons(ARPHRD_ETHER);
	arp->ar_pro = htons(ETH_P_IP);
	arp->ar_hln = 6;
	arp->ar_pln = 4;
	arp->ar_op = htons(ARPOP_REQUEST);
	memcpy(arp->ar_sha, ifr.ifr_hwaddr.sa_data, 6);

	close(s);
	return 1;
ERR:
	if (s>=0)
		close(s);
	return 0;

}
int send_arprequst()
{
	//sometimes when code run into here, but wan interface still can't get ip address, then will send a lot of arp packet, so before send arp packet, we make sure wan interface have got ip address
	dni_system(NULL, "/etc/init.d/net-wan", "restart", NULL);
	/*
	 *if the ip address is not the same, send arp ping to all subnet,(except loopback, broadcast, gateway ip address) through the WAN interface.
	 *Each IP address send 3 times at the same time, wait 3 seconds, if no response, repeat again, totally try 3 times.
	 */
	int buffersize = 200 * 1024;
	struct sockaddr me;
	int arp_sock=socket(PF_PACKET,SOCK_PACKET,htons(ETH_P_ARP));

	int resp_code = 0;
	/* We're trying to override buffer size  to set a bigger buffer. */
	if( setsockopt(arp_sock,SOL_SOCKET, SO_RCVBUF, &buffersize, sizeof(buffersize)))
		fprintf(stderr, "setsocketopt error!\n");

	me.sa_family=PF_PACKET;
	strncpy(me.sa_data,wan_if_name,14);
	bind(arp_sock,&me,sizeof(me));

	int trytimes = 0;
	pid_t pid_request;
	struct in_addr wan_ipaddr;
	struct in_addr wan_netmask;
	wan_ipaddr.s_addr = 0;
	wan_netmask.s_addr = 0;
	unsigned long wan_subnet, wan_brodcast;

	//it will not going on unless we get the IP or try to get it for 10 times
	do{
		wan_ipaddr = get_ipaddr(wan_if_name);
		wan_netmask = get_netmask(wan_if_name);
		if (strcmp(inet_ntoa(wan_ipaddr),"0.0.0.0") != 0)
			break;
		sleep(2);	
	}while(trytimes++ < 10);

	//if we try more than times return 0.
	if (trytimes > 10){
		resp_code = 1;
		goto Err;
	}
	init_arp_request(wan_if_name);
	//for debug
	FILE *cfp=NULL;
	cfp = fopen("/dev/console", "r+");

	wan_subnet = (wan_ipaddr.s_addr) & (wan_netmask.s_addr);
	wan_brodcast = (wan_ipaddr.s_addr) | (~wan_netmask.s_addr);
			
	struct in_addr wan_inaddr;
	wan_inaddr.s_addr = wan_subnet + htonl(1);
			
	//for debug
	struct in_addr test_inaddr1;
	test_inaddr1.s_addr = wan_subnet + htonl(1);

	struct in_addr test_inaddr2;
	test_inaddr2.s_addr = wan_brodcast - htonl(1);

	if( cfp ){
		fprintf( cfp, "echo '[AP mode autodetection] wan_ipaddr: %s'\n", inet_ntoa(wan_ipaddr));
		fprintf( cfp, "echo '[AP mode autodetection] wan_netmask: %s'\n", inet_ntoa(wan_netmask));
		fprintf( cfp, "echo '[AP mode autodetection]ARP request start: %s ' \n", inet_ntoa(test_inaddr1));
		fprintf( cfp, "echo '[AP mode autodetection]ARP request end: %s ' \n", inet_ntoa(test_inaddr2));
	}

	unsigned long cur_addr;
	char *cur_ip;
	uint8 cur_destip[4];
	fd_set readset;
	int max_sock=arp_sock+1;
	struct timeval timeout;
	int time_count;
	unsigned long wan_gateway;
	uint8 wangateway_mac[6];
	memset(wangateway_mac,0x0,6);
	wan_gateway = inet_addr(get_conf_string("wan_dhcp_gateway"));
	//send arp packet to get wan gateway mac
	if (((uint8 *) &wan_gateway)!= NULL)
	{
		memcpy(arpreq.ar_tip,(uint8 *)&wan_gateway,4);
		sendto(arp_sock,&arpreq,sizeof(struct arpmsg),0,&me,sizeof(struct sockaddr));
		//listen socket to check whether arp request comes
		timeout.tv_sec=3;
		time_t start;
		time(&start);
		while(timeout.tv_sec >= 0)
		{
			struct arpmsg arp_packet;
			struct sockaddr arp_from;
			socklen_t arp_len;
			int blen;
			FD_ZERO(&readset);
			FD_SET(arp_sock,&readset);
			int sec = select(max_sock,&readset,0,0,&timeout);
 			if(sec == 0)
				break;
			time_t now;
			time(&now);
			timeout.tv_sec = 3 - (now - start);
			if(FD_ISSET(arp_sock,&readset))
				blen=recvfrom(arp_sock,&arp_packet,sizeof(arp_packet),0,(struct sockaddr *) &arp_from, &arp_len);
			else
				blen=0;
			if(blen>=42)
			{
				if(arp_packet.ar_op == htons(ARPOP_REPLY)&&(memcmp((uint8 *)&wan_gateway,arp_packet.ar_sip,4)==0))
				{
					uint8 * wangateway = (uint8 *)ether_ntoa((const struct ether_addr *)wangateway_mac);
					memcpy(wangateway_mac,arp_packet.ar_sha,6);
					if( cfp )
						fprintf(cfp, "echo '[AP autodetection]  recv first wangateway_mac %s'\n", wangateway);
					break;
 				}
			}
		}
	}
	if ( (pid_request = fork()) <0 )
		printf("fork error to send arp request!\n");
	else if ( pid_request == 0 ){
		for( time_count=0; time_count<3;time_count++)
		{
			for(cur_addr=wan_subnet+htonl(1);cur_addr<wan_brodcast; )
			{
				wan_inaddr.s_addr = cur_addr;
				cur_ip=inet_ntoa(wan_inaddr);
				//printf("[AP autodetection] arp request cur_ip is = %s\n", cur_ip);
				if((strcmp(cur_ip,"127.0.0.1")==0)||(strcmp(cur_ip,get_conf_string("wan_dhcp_ipaddr"))==0)||(strcmp(cur_ip,get_conf_string("wan_dhcp_gateway"))==0))
				{
					cur_addr = ntohl(cur_addr);
					cur_addr++;
					cur_addr = htonl(cur_addr);
					continue;
				}
				memcpy(cur_destip,(uint8 *)&cur_addr,4);
				int count_sendarp=0;
				while(count_sendarp !=3)
				{
					count_sendarp++;
					memcpy(arpreq.ar_tip,cur_destip,4);
					sendto(arp_sock,&arpreq,sizeof(struct arpmsg),0,&me,sizeof(struct sockaddr));
				}
				cur_addr = ntohl(cur_addr);
				cur_addr++;
				cur_addr = htonl(cur_addr);
				
				//wan_inaddr.s_addr = cur_addr;
				//cur_ip=inet_ntoa(wan_inaddr);
				//printf("[AP autodetection] arp request cur_ip cccc = %s\n", cur_ip);
			}
			sleep(3);
		}
		resp_code=2;
		goto Err;
	}
	int alen;
	timeout.tv_sec=9;
	time_t start;
	time(&start);
	//If we didn't set the loop out condition, when arp response form own ip or gateway, it'll can't loop out
	while(timeout.tv_sec >= 0)
	{
		//listen socket to check whether arp request comes
		//printf("[AP autodetection] time_count is  = %d\n", time_count);
		//printf("[AP autodetection] currently time timeout.tv_sec is =  %d\n",timeout.tv_sec);
		FD_ZERO(&readset);
		FD_SET(arp_sock,&readset);
		int ret = select(max_sock,&readset,0,0,&timeout);
		if(ret == 0)
			break;
		time_t now;
		time(&now);
		timeout.tv_sec = 9 - (now - start); 
		struct arpmsg arp_packet;
		struct sockaddr arp_from;
		socklen_t arp_len;
		if(FD_ISSET(arp_sock,&readset))
			alen=recvfrom(arp_sock,&arp_packet,sizeof(arp_packet),0,(struct sockaddr *) &arp_from, &arp_len);
		else
			alen=0;
		if(alen>=42)
		{
			if(arp_packet.ar_op == htons(ARPOP_REPLY)&&(memcmp(ap_autodection_wanaddress1,arp_packet.ar_tip,4)==0))
			{
				//for debug 
				//char cmd_4[256];
				printf("[AP autodetection] recv arp response %d.%d.%d.%d\n",arp_packet.ar_sip[0],arp_packet.ar_sip[1],arp_packet.ar_sip[2],arp_packet.ar_sip[3]);
				//snprintf(cmd_4,256,"echo '[AP autodetection] 111recv arp response %d.%d.%d.%d' > /dev/console",arp_packet.ar_sip[0],arp_packet.ar_sip[1],arp_packet.ar_sip[2],arp_packet.ar_sip[3]);
				//system(cmd_4);
				unsigned long wan_ownip=inet_addr(get_conf_string("wan_dhcp_ipaddr"));
				if((memcmp((uint8 *)&wan_gateway,arp_packet.ar_sip,4)==0)||(memcmp((uint8 *)&wan_ownip,arp_packet.ar_sip,4)==0))
				{
					//system("echo '[AP autodetection] ignore arp response form own ip or gateway' > /dev/console");
					printf("[AP autodetection] ignore arp response form own ip or gateway\n");
					continue;
				}
				else if((memcmp(wangateway_mac,arp_packet.ar_sha,6))==0)
				{
					resp_code = 3;
					goto Err;
				}
				else{
					resp_code = 4;
					goto Err;
				}
			}
		}
	}
	resp_code=1;
Err:
	if(arp_sock>=0)
		close(arp_sock);
	if(cfp)
		fclose(cfp);
	switch(resp_code){
		case 1:
			return 0;
		case 2:
			return -1;
		case 3:
			return 2;
		case 4:
			return 1;
		default:
			return -1;
	}
}

void AP_autodection(uint8 *dutMac)
{

	/* Set the network card in promiscuos mode */
	set_promisc(wan_if_name);

	int bpa; // we don't need this parameter in this AP mode autodetection feature, but just for using the function which has been realized
	int is_DHCP;
	static uint8 ip_zero[4] = { 0, 0, 0, 0 };

	memset(ap_autodection_wanaddress1,0x0,4);
	memset(ap_autodection_wanaddress2,0x0,4);
	if((is_DHCP=DHCP_Detection(&bpa,dutMac))){
		/*
		 *if wan is DHCP mode, then will send dhcp request with different mac address (use routermac address +1) 
		 * check the ip address is the same.
		 */
		count++;
		uint8 newMac[6];
		memcpy(newMac,dutMac,6);
		newMac[5]++;
		DHCP_Detection(&bpa,newMac);
		//check the ip address is the same
		printf("[AP autodetection] ap_autodection_wanaddress1 is %d.%d.%d.%d\n",ap_autodection_wanaddress1[0],ap_autodection_wanaddress1[1],ap_autodection_wanaddress1[2],ap_autodection_wanaddress1[3]);
		printf("[AP autodetection] ap_autodection_wanaddress2 is %d.%d.%d.%d\n",ap_autodection_wanaddress2[0],ap_autodection_wanaddress2[1],ap_autodection_wanaddress2[2],ap_autodection_wanaddress2[3]);
		
		//To fix bug 43910, when the server didn't response for the second discover(mac+1), we should take it as response the same
#if ORBI
		if(Check_IP_Type()==1)
#ifdef SUPPORT_SR_CDLESS
			system("echo 1 > /tmp/cache/cdless/check_ap_result");
#else
			system("echo 1 > /tmp/result_ap_autodetection");
#endif
		else
#endif
		if( (memcmp(ap_autodection_wanaddress1, ap_autodection_wanaddress2, 4) == 0  
					&& (memcmp(ap_autodection_wanaddress1, ip_zero, 4) != 0) && (memcmp(ap_autodection_wanaddress2, ip_zero, 4) != 0 )) 
		 			|| ((memcmp(ap_autodection_wanaddress1, ip_zero, 4) != 0) && (memcmp(ap_autodection_wanaddress2, ip_zero, 4) == 0 )) )
		{
			//for one US cable modem
			//the behavior is that cable modem only can assign 1 ip address to router
			printf("[AP autodetection] the ip address is the same\n");
			//if the ip address is the same, detection is done, Go to "Checking Internet connection" page
#ifdef SUPPORT_SR_CDLESS
			system("echo 1 > /tmp/cache/cdless/check_ap_result");
#else
			system("echo 1 > /tmp/result_ap_autodetection");
#endif

		}
		else if( (memcmp(ap_autodection_wanaddress1, ap_autodection_wanaddress2, 4) != 0) 
		    && (memcmp(ap_autodection_wanaddress1, ip_zero, 4) != 0) && (memcmp(ap_autodection_wanaddress2, ip_zero, 4) != 0 ) )
		{
			// Follow NETGEAR new spec, when ip address is not the same, we need to go to "ap mode & router mode optional page"
			printf("[AP autodetection] the ip address is NOT the same\n");
			//if the ip address is the same, detection is done, Go to "Checking Internet connection" page
#ifdef SUPPORT_SR_CDLESS
			system("echo 0 > /tmp/cache/cdless/check_ap_result");
#else
			system("echo 0 > /tmp/result_ap_autodetection");
#endif

		}
		else
		{
			int result = send_arprequst();
			if (result == 1)
			{
#ifdef SUPPORT_SR_CDLESS
				system("echo 0 > /tmp/cache/cdless/check_ap_result");
#else
				system("echo 0 > /tmp/result_ap_autodetection");
#endif
			}
			else if (result == 2)
			{
#ifdef SUPPORT_SR_CDLESS
				system("echo 1 > /tmp/cache/cdless/check_ap_result");
#else
				system("echo 1 > /tmp/result_ap_autodetection");
#endif
			}
			else if (result == -1)
			{
				exit(0);
			}
			else
			{
				//if arp ping no response, then detect if DNS is the same as gateway 
				// yes, Detection is done, show ap mode & router mode optional page
				// no, Detection is done ,go to "checking internet connection" page
				printf("[AP autodetection] arp ping no response or arp response invalid! \n");
				FILE *fp;
				char *dhcp_gateway;
				char cmd_6[256];
				char dns_gate[256];

				dhcp_gateway = get_conf_string("wan_dhcp_gateway");
				snprintf(cmd_6,256,"grep %s /tmp/resolv.conf > /tmp/ABC_result", dhcp_gateway);
				system(str_replace(cmd_6));
				fp=fopen("/tmp/ABC_result","r");
				fgets(dns_gate,sizeof(dns_gate),fp);
				fclose(fp);
				if(strncmp(dns_gate,"nameserver",10)==0)
#ifdef SUPPORT_SR_CDLESS
					system("echo 0 > /tmp/cache/cdless/check_ap_result");
#else
					system("echo 0 > /tmp/result_ap_autodetection");
#endif
				else
#ifdef SUPPORT_SR_CDLESS
					system("echo 1 > /tmp/cache/cdless/check_ap_result");
#else
					system("echo 1 > /tmp/result_ap_autodetection");
#endif
			}
		}
	}
	else
	{
		//if wan is not DHCP mode
		//Detection is done, Go to "Checking Internet connection" page
#ifdef SUPPORT_SR_CDLESS
		system("echo 1 > /tmp/cache/cdless/check_ap_result");
#else
		system("echo 1 > /tmp/result_ap_autodetection");
#endif
	}
	unset_promisc(wan_if_name);
}
void AP_autodection_lan(uint8 *dutMac)
{
	int bpa;
	int is_DHCP;

	/* Set the network card in promiscuos mode */
	set_promisc(wan_if_name);

	if((is_DHCP=DHCP_Detection(&bpa,dutMac))){
#ifdef SUPPORT_SR_CDLESS
		system("echo 0 > /tmp/cache/cdless/check_ap_result");
#else
		system("echo 0 > /tmp/result_ap_autodetection");
#endif
	}
	else
	{
#ifdef SUPPORT_SR_CDLESS
		dni_system( "/tmp/cache/cdless/check_ap_result", "/bin/echo", "1", NULL);
#else
		dni_system( "/tmp/result_ap_autodetection" , "/bin/echo", "1", NULL);
#endif
	}

	unset_promisc(wan_if_name);
}
