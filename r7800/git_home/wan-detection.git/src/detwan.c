#include "internet.h"
#include "config_file.h"

//for AP autodecteion feature
extern int flag_apautodection;
extern int count;
extern uint8 ap_autodection_wanaddress1[4];
extern uint8 ap_autodection_wanaddress2[4];


/*======================================================
                                                    [ PPPoE Detection ]
    ======================================================*/
/* an NUL 'Service-Name' tag && a 'Host-Uniq' tag with PID value */
#define PADI_PAYLOAD_SIZE	((2 * PPPOE_TAG_SIZE) + sizeof(pid_t))

/* Keep track of the state of a connection -- collect everything in one spot */
typedef struct PPPoEConnectionStruct {
	int discoveryState;			/* Where we are in discovery */
	uint16 sid;					/* Session ID */
	uint8 cookie[MAX_PKT_SIZE];		/* We have send this if we get it */
	uint8 relayId[MAX_PKT_SIZE];	/* Ditto */
	uint8 peerEth[ETH_ALEN];		/* Peer's MAC address */
	char *serviceName;			/* Desired service name, if any */
	int useHostUniq;				/* Use Host-Uniq tag */
	int seenACName;
	int seenServiceName;
} PPPoEConnection;

#if 1
#define DB prt2scrn
#else
#define DB printf
#endif

void prt2scrn(char *fmt, ...)
{
	FILE *fp;
	va_list arglist;
	if ((fp = fopen("/dev/console", "w")) == NULL)
		return;
	va_start(arglist, fmt);
	vfprintf(fp, fmt, arglist);
	va_end(arglist);
	fclose(fp);
}

static int init_PADI(struct pppoe_packet *packet, PPPoEConnection *conn, uint8 *hwaddr)
{
	struct pppoe_tag *svc;

	memset(packet->h_dest, 0xFF, ETH_ALEN);
	memcpy(packet->h_source, hwaddr, ETH_ALEN);
	packet->h_proto = htons(ETH_PPPOE_DISC);

	packet->ver_type = 0x11;
	packet->code = CODE_PADI;
	packet->sid = 0;
	packet->length = htons(PADI_PAYLOAD_SIZE);

	/* Add an NUL 'Service-Name' tag */
	svc = (struct pppoe_tag *)(packet->data);
	svc->tag_type = htons(TAG_SERVICE_NAME);
	svc->tag_len = 0;

	/* Add 'Host-Uniq' tag with PID value */
	svc++;
	pid_t pid = getpid();
	svc->tag_type = htons(TAG_HOST_UNIQ);
	svc->tag_len = htons(sizeof(pid_t));
	memcpy(svc->tag_data, &pid, sizeof(pid_t));
	/* Mark that pppoe connection use the tag host unique */
	conn->useHostUniq = 1;

	return (ETH_HDRSIZE + PPPOE_HDRSIZE + PADI_PAYLOAD_SIZE);
}

static int open_DiscSocket(uint8 *hwaddr)
{
	int fd;
	int optval = 1;    	
	struct ifreq ifr;
	struct sockaddr_ll sa;

	memset(&sa, 0, sizeof(sa));
	fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_PPPOE_DISC));
	if (fd < 0) {
		DB("PPPoE socket failed.\n");
		return -1;
	}
	
	if (setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &optval, sizeof(optval)) < 0)
		goto err;
	
	strncpy(ifr.ifr_name, wan_if_name, sizeof(ifr.ifr_name));
	if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
		DB("Can't get %s mac.\n", wan_if_name);
		goto err;
	}
	memcpy(hwaddr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
	
	strncpy(ifr.ifr_name, wan_if_name, sizeof(ifr.ifr_name));
	if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0)
		goto err;	

	sa.sll_ifindex = ifr.ifr_ifindex;
	sa.sll_family = AF_PACKET;
	sa.sll_protocol = htons(ETH_PPPOE_DISC);
	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		DB("PPPoE bind failed.\n");
		goto err;
	}

	return fd;
	
err:
	close(fd);
	return -1;
}

static void parsePADOPacket(struct pppoe_packet *packet, 
		PPPoEConnection *conn)
{
	int i;
	uint16 len;
	uint8 *curTag;
	uint8 *tagData;
	uint16 tagType, tagLen;
		
	len = ntohs(packet->length);
	if (len > PPPOE_DATA_LEN) {
		DB("Invalid PPPoE packet length (%u)", len);
		return;
	}
	
	if (packet->ver_type != 0x11) {
		DB("Invalid version or type.\n");
		return;
	}

	/* Save the PPPoE server MAC address */
	memcpy(conn->peerEth, packet->h_source, ETH_ALEN);

	curTag = packet->data;
	while (curTag - packet->data < len) {
		tagType	= TAG_TYPE(curTag);
		tagLen	= TAG_LEN(curTag);
		tagData	= curTag + PPPOE_TAG_SIZE;

		if (tagType == TAG_END_OF_LIST)
			return;

		if ((tagData - packet->data) + tagLen > len) {
			DB("Invalid PPPoE tag length (%u)", tagLen);
			return;
		}

		if (tagType == TAG_AC_NAME) {
			conn->seenACName = 1;
			DB("Access-Concentrator: %.*s\n", (int) tagLen, tagData);
		} else if (tagType == TAG_SERVICE_NAME) {
			conn->seenServiceName = 1;
			DB("Service-Name: %.*s\n", (int) tagLen, tagData);
		} else if (tagType == TAG_RELAY_SESSION_ID) {
			struct pppoe_tag *relayId = (struct pppoe_tag *)conn->relayId;
			DB("Got a Relay-ID:");
			/* Print first 20 bytes of relay ID */
			for (i=0; i<tagLen && i<20; i++) {
				DB(" %02x", (unsigned)tagData[i]);
			}
			if (i<tagLen) DB("...");
			DB("\n");

			relayId->tag_type = htons(tagType);
			relayId->tag_len = htons(tagLen);
			memcpy(relayId->tag_data, tagData, tagLen);
		} else if (tagType == TAG_AC_COOKIE) {
			struct pppoe_tag *cookie = (struct pppoe_tag *)conn->cookie;
			DB("Got a cookie:");
			/* Print first 20 bytes of cookie */
			for (i=0; i<tagLen && i<20; i++) {
				DB(" %02x", (unsigned)tagData[i]);
			}
			if (i<tagLen) DB("...");
			DB("\n");

			cookie->tag_type = htons(tagType);
			cookie->tag_len = htons(tagLen);
			memcpy(cookie->tag_data, tagData, tagLen);
		}

		curTag = tagData + tagLen;
	}
}

/*********************************************************
*%FUNCTION: packetIsForMe
*%ARGUMENT:
* conn -- PPPoE connection info
* packet -- a received PPPoE packet
*%RETURN:
* 1 if packet is for this PPPoE daemon; 0 otherwise.
*%DESCRIPTION:
* If we are using the Host-Unique tag, verifies that packet contains
* our unique identifier.
**********************************************************/
static int packetIsForMe(PPPoEConnection *conn, uint8 *hwaddr, struct pppoe_packet *packet)
{
	uint16 len;
	uint8 *curTag;
	uint8 *tagData;
	uint16 tagType, tagLen;

	/* If packet is not directed to our MAC address, forget it */
	if (memcmp(packet->h_dest, hwaddr, ETH_ALEN)) return 0;

	/* If we're not using the Host-Unique tag, the accept the packet */
	if (!conn->useHostUniq) return 1;

	/* If a HostUnique tag is found which matches our PID, accpet the packet */
	len = ntohs(packet->length);
	curTag = packet->data;
	while (curTag - packet->data < len) {
		tagType	= TAG_TYPE(curTag);
		tagLen	= TAG_LEN(curTag);
		tagData	= curTag + PPPOE_TAG_SIZE;

		if (tagType == TAG_END_OF_LIST)
			break;

		if ((tagData - packet->data) + tagLen > len) {
			DB("Invalid PPPoE tag length (%u)", tagLen);
			return 0;
		}

		if (tagType == TAG_HOST_UNIQ && tagLen == sizeof(pid_t)) {
			pid_t tmp;
			memcpy(&tmp, tagData, tagLen);
			if (tmp != getpid()) {
				return 0;
			} else {
				return 1;
			}
		}

		curTag = tagData + tagLen;
	}

	return 0;
}

static int waitForPADO(int fd, PPPoEConnection *conn, uint8 *hwaddr)
{
	int r, len;
	int tries = 5;
	fd_set readable;
	struct timeval tv;
	struct pppoe_packet packet;
	
	for (;;) {
		if (--tries < 0)
			return 0;

		tv.tv_sec = PPPOE_TIMEOUT;
		tv.tv_usec = 0;
		FD_ZERO(&readable);
		FD_SET(fd, &readable);
		
		r = select(fd + 1, &readable, NULL, NULL, &tv);
		if (r < 0)
			continue;
		if (r == 0)
			continue;
		len = recv(fd, &packet, sizeof(struct pppoe_packet), 0);
		if (ntohs(packet.length) + ETH_HDRSIZE + PPPOE_HDRSIZE > len ||
		    memcmp(packet.h_dest, hwaddr, ETH_ALEN) ||
		    packet.code != CODE_PADO)
			continue;
		/* If it's not for us, loop again */
		if (!packetIsForMe(conn, hwaddr, &packet)) continue;

		parsePADOPacket(&packet, conn);
		if (conn->seenACName && conn->seenServiceName)
			return 1;
	}

	return 0;
}

static int init_PADR(struct pppoe_packet *packet, PPPoEConnection *conn, uint8 *hwaddr )
{
	struct pppoe_tag *svc;
	uint8 *cursor = packet->data;
	uint16 namelen = 0;
	uint16 plen = 0;
	/* FIXME checkroom */

	memcpy(packet->h_dest, conn->peerEth, ETH_ALEN);
	memcpy(packet->h_source, hwaddr, ETH_ALEN);
	packet->h_proto = htons(ETH_PPPOE_DISC);

	packet->ver_type = 0x11;
	packet->code = CODE_PADR;
	packet->sid = 0;

	/* Add 'service-name' tag */
	DB("add service-name tag\n");
	svc = (struct pppoe_tag *)cursor;
	svc->tag_type = htons(TAG_SERVICE_NAME);
	if (conn->serviceName) {
		DB("line = %d\n", __LINE__);
		namelen = (uint16)strlen(conn->serviceName);
		svc->tag_len = htons(namelen);
		memcpy(svc->tag_data, conn->serviceName, namelen);
	} else {
		DB("line = %d\n", __LINE__);
		namelen = 0;
		svc->tag_len = 0;
	}
	cursor += namelen + PPPOE_TAG_SIZE;
	plen += namelen + PPPOE_TAG_SIZE;

	/* If we're using Host-Uniq, copy it over */
	if (conn->useHostUniq) {
	DB("add host unique tag\n");
	struct pppoe_tag *hostUniq = (struct pppoe_tag *)cursor;
	pid_t pid = getpid();
	hostUniq->tag_type = htons(TAG_HOST_UNIQ);
	hostUniq->tag_len = htons(sizeof(pid));
	/* check room */
	memcpy(hostUniq->tag_data, &pid, sizeof(pid));
	cursor += sizeof(pid) + PPPOE_TAG_SIZE;
	plen += sizeof(pid) + PPPOE_TAG_SIZE;
	}

	/* Copy cookie and relay-ID if needed */
	struct pppoe_tag *cookie = (struct pppoe_tag *)conn->cookie;
	if(cookie->tag_type) {
		DB("add relay-ID tag\n");
		/* check room */
		memcpy(cursor, cookie, ntohs(cookie->tag_len) + PPPOE_TAG_SIZE);
		cursor += ntohs(cookie->tag_len) + PPPOE_TAG_SIZE;
		plen += ntohs(cookie->tag_len) + PPPOE_TAG_SIZE;
	}

	struct pppoe_tag *relayId = (struct pppoe_tag *)conn->relayId;
	if(relayId->tag_type) {
		DB("add relayID tag\n");
		/* check room */
		memcpy(cursor, relayId, ntohs(relayId->tag_len) + PPPOE_TAG_SIZE);
		cursor += ntohs(relayId->tag_len) + PPPOE_TAG_SIZE;
		plen += ntohs(relayId->tag_len) + PPPOE_TAG_SIZE;
	}

	packet->length = htons(plen);

	return (ETH_HDRSIZE + PPPOE_HDRSIZE +plen);
}

static int init_PADT(struct pppoe_packet *packet, PPPoEConnection *conn, uint8 *hwaddr )
{
	uint8 *cursor = packet->data;
	uint16 plen = 0;
	/* Do nothing if no session established yet */
	if (!conn->sid) return -1;

	/* FIXME checkroom */

	memcpy(packet->h_dest, conn->peerEth, ETH_ALEN);
	memcpy(packet->h_source, hwaddr, ETH_ALEN);
	packet->h_proto = htons(ETH_PPPOE_DISC);

	packet->ver_type = 0x11;
	packet->code = CODE_PADT;
	packet->sid = conn->sid;

	/* Reset Session to zero so there is no possibility of
	 * recursive calls to this function in case */
	conn->sid = 0;

	/* If we're using Host-Uniq, copy it over */
	if (conn->useHostUniq) {
	DB("add host unique tag\n");
	struct pppoe_tag *hostUniq = (struct pppoe_tag *)cursor;
	pid_t pid = getpid();
	hostUniq->tag_type = htons(TAG_HOST_UNIQ);
	hostUniq->tag_len = htons(sizeof(pid));
	/* check room */
	memcpy(hostUniq->tag_data, &pid, sizeof(pid));
	cursor += sizeof(pid) + PPPOE_TAG_SIZE;
	plen += sizeof(pid) + PPPOE_TAG_SIZE;
	}

	/* Write the terminate reason */
	char *msg = "Complete the PPPoE Discovery handshake process, Bye Bye ^_^V !";
	struct pppoe_tag *emsg = (struct pppoe_tag *)cursor;
	emsg->tag_type = htons(TAG_GENERIC_ERROR);
	emsg->tag_len = htons(strlen(msg));
	strcpy((char *)emsg->tag_data, msg);
	cursor += ntohs(emsg->tag_len) + PPPOE_TAG_SIZE;
	plen += ntohs(emsg->tag_len) + PPPOE_TAG_SIZE;

	/* Copy cookie and relay-ID if needed */
	struct pppoe_tag *cookie = (struct pppoe_tag *)conn->cookie;
	if(cookie->tag_type) {
		DB("add relay-ID tag\n");
		/* check room */
		memcpy(cursor, cookie, ntohs(cookie->tag_len) + PPPOE_TAG_SIZE);
		cursor += ntohs(cookie->tag_len) + PPPOE_TAG_SIZE;
		plen += ntohs(cookie->tag_len) + PPPOE_TAG_SIZE;
	}

	struct pppoe_tag *relayId = (struct pppoe_tag *)conn->relayId;
	if(relayId->tag_type) {
		DB("add relayID tag\n");
		/* check room */
		memcpy(cursor, relayId, ntohs(relayId->tag_len) + PPPOE_TAG_SIZE);
		cursor += ntohs(relayId->tag_len) + PPPOE_TAG_SIZE;
		plen += ntohs(relayId->tag_len) + PPPOE_TAG_SIZE;
	}

	packet->length = htons(plen);

	return (ETH_HDRSIZE + PPPOE_HDRSIZE +plen);
}

static int waitForPADS(int fd, PPPoEConnection *conn, uint8 *hwaddr)
{
	int r, len;
	int tries = 5;
	fd_set readable;
	struct timeval tv;
	struct pppoe_packet packet;
	memset(&packet, 0x0, sizeof(struct pppoe_packet));

	for (;;) {
		if (--tries < 0)
			return 0;

		tv.tv_sec = PPPOE_TIMEOUT;
		tv.tv_usec = 0;
		FD_ZERO(&readable);
		FD_SET(fd, &readable);

		r = select(fd + 1, &readable, NULL, NULL, &tv);
		if (r <= 0)
			continue;
		len = recv(fd, &packet, sizeof(struct pppoe_packet), 0);
		DB("line = %d, recv len=%d\n", __LINE__, len);
		DB("line = %d, packet.code=0x%x, packet.length=%d\n", __LINE__, packet.code, ntohs(packet.length));
		if (ntohs(packet.length) + ETH_HDRSIZE + PPPOE_HDRSIZE > len ||
		    memcmp(packet.h_dest, hwaddr, ETH_ALEN) ||
		    packet.code != CODE_PADS) {
			/* May receive PADO packet, skip it without the tries decrease */
			if (packet.code != CODE_PADS) {
				DB("Reveive the previous PPPoE PADO packet, ignore it\n");
				tries++;
			}
			continue;
		}
		/* If it's not for us, loop again */
		if (!packetIsForMe(conn, hwaddr, &packet)) continue;

		/* Got the PADS packet, and save the session id.
		 * Don't bother with ntohs; we'll just end up converting it back... */
		conn->sid = packet.sid;

		return 1;
	}

	return 0;
}

/*Add black list*/
char *str_replace(char *str)
{
	char c, *p;
	static char buf[32];

	p = buf;
	uint32 i = 0;
	while((c = str[i]) != '\0') {
		if(c == '&') {
			*p++=' ';
		} else if (c == ';') {
			*p++=' ';
		} else if (c == '|') {
			*p++=' ';
		} else if (c == '$') {
			*p++=' ';
		} else if (c == '(') {
			*p++=' ';
		} else if (c == ')') {
			*p++=' ';
		} else if (c == '`') {
			*p++=' ';
		} else {
			*p++=c;
		}
		i++;
	}
	*p='\0';
	return buf;
}

static int PPPoE_Detection(uint8 *hwaddr)
{
	int i;
	int ret, fd, plen;
	struct pppoe_packet padiPacket;
	struct pppoe_packet padrPacket;
	struct pppoe_packet padtPacket;
	/* Save all the connection status here */
	PPPoEConnection connection;

	memset(&padiPacket, 0x0, sizeof(struct pppoe_packet));
	memset(&padrPacket, 0x0, sizeof(struct pppoe_packet));
	memset(&padtPacket, 0x0, sizeof(struct pppoe_packet));
	memset(&connection, 0x0, sizeof(PPPoEConnection));

	ret = 0;
	fd = open_DiscSocket(hwaddr);

	if (fd == -1)
		return 0;

	plen = init_PADI(&padiPacket, &connection, hwaddr);

	for (i = 0; i < 3; i++) {
		send(fd, &padiPacket, plen, 0);
		connection.discoveryState = STATE_SENT_PADI;
		ret = waitForPADO(fd, &connection, hwaddr);
		sleep(2);
		if (ret == 1) {
			connection.discoveryState = STATE_RECEIVED_PADO;
		}
	}
	DB("discoveryState = %d\n", connection.discoveryState);
	if (connection.discoveryState != STATE_RECEIVED_PADO) {
		DB("close fd due to status error\n");
		close(fd);
		return 0;
	}

	DB("init PADR packet\n");
	plen = init_PADR(&padrPacket, &connection, hwaddr);
	DB("init_PADR packet size = %d\n", plen);
	for (i = 0; i < 2; i++) {
		int sdlen;
		sdlen = send(fd, &padrPacket, plen, 0);
		DB("plen = %d, actual send PADR length = %d\n", plen, sdlen);

		connection.discoveryState = STATE_SENT_PADR;
		ret = waitForPADS(fd, &connection, hwaddr);
		if (ret == 1) {
			connection.discoveryState = STATE_SESSION;
			break;
		}
	}
	DB("discoveryState = %d\n", connection.discoveryState);
	if (connection.discoveryState != STATE_SESSION) {
		close(fd);
		return 0;
	}

	/* The router has to terminate the PPPoE session just created before exit */
	if (init_PADT(&padtPacket, &connection, hwaddr) > 0){
		plen = init_PADT(&padtPacket, &connection, hwaddr);
		DB("init_PADT packet size = %d\n", plen);
		send(fd, &padtPacket, plen, 0);
	}

	close(fd);
	return 1;
}

/*======================================================
                                                  [ DHCP & BPA Detection ]
    ======================================================*/

/* Compute Internet Checksum for "count" bytes
  * beginning at location "addr".
 */
static uint16 calc_csum(void *addr, int count)
{
	int sum = 0;
	uint16 *source = (uint16 *)addr;

	while (count > 1) {
		sum += *source++;
		count -= 2;
	}

	/*  add left-over byte, if any */
	if (count > 0) {
		/* Make sure that the left-over byte is added correctly both
		 * with little and big endian hosts */
		uint16 left = 0;
		*(uint8 *) (&left) = *(uint8 *)source;
		sum += left;
	}

	/*  fold 32-bit sum to 16 bits */
	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);

	return (uint16)(~sum);
}

static int raw_socket()
{
	int fd;
	int optval = 1;

	fd = socket(PF_PACKET, SOCK_PACKET, htons(ETH_P_IP));
	if (fd < 0)
		return -1;

	if (setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &optval, sizeof(optval)) == -1) {
		perror("setsockopt");
		close(fd);
		return -1;
	}

	return fd;
}

static int add_option(uint8 *op, uint8 code, int len, void *data)
{	
	op[OPT_CODE] = code;
	op[OPT_LEN] = (uint8)len;

	memcpy(&op[OPT_DATA], data, len);

	return (len + 2);
}

static uint8 *get_option(struct dhcpMessage *packet, uint8 opcode, uint8 *oplen)
{
	int i, len;
	uint8 *op;
	int over = 0, done = 0, curr = OPTION_FIELD;

	i = 0;
	len = OPT_SIZE;
	op = packet->options;

	while(!done) {
		if (op[i + OPT_CODE] == opcode) {
			if (i + 1 + op[i + OPT_LEN] >= len)
				return NULL;
			*oplen = op[i + OPT_LEN];
			return op + i + 2;
		}

		switch (op[i + OPT_CODE]) {
		case DHCP_PADDING:
			i++;
			break;

		case DHCP_OPTION_OVER:
			if (i + 1 + op[i + OPT_LEN] >= len)
				return NULL;

			over = op[i + 3];
			i += op[OPT_LEN] + 2;
			break;

		case DHCP_END:
			if (curr == OPTION_FIELD && over & FILE_FIELD) {
				op = packet->file;
				i = 0;
				len = 128;
				curr = FILE_FIELD;
			} else if (curr == FILE_FIELD && over & SNAME_FIELD) {
				op = packet->sname;
				i = 0;
				len = 64;
				curr = SNAME_FIELD;
			} else {
				done = 1;
			}
			break;

		default:
			i += op[OPT_LEN + i] + 2;
		}
	}

	return NULL;
}

static int init_discover(struct rawPacket *packet, uint32 xid, uint8 *arp)
{
	int dhcp_len;
	int packet_len;
	uint8 msgtype, *op, id[7];
	struct dhcpMessage *dmsg;
	static uint8 reqlist[] = { 0x01, 0x03, 0x06, 0x0c, 0x0f, 0x1c };

	msgtype = DHCPDISCOVER;
	id[0] = ETH_10MB;
	memcpy(&id[1], arp, 6);
	memset(packet, 0, sizeof(struct rawPacket));
	
	/*********************************************************/
	dmsg = &packet->data;
	dmsg->op = BOOTREQUEST;
	dmsg->htype = ETH_10MB;
	dmsg->hlen = ETH_10MB_LEN;
	dmsg->xid = htonl(xid);
	dmsg->cookie = htonl(DHCP_MAGIC);
	
	memcpy(dmsg->chaddr, arp, 6);
	/* option */
	op = dmsg->options;
	op += add_option(op, DHCP_MESSAGE_TYPE, 1, &msgtype);
	if(!get_conf_bool("detwan_have_dsl"))
		op += add_option(op, DHCP_CLIENT_ID, 7, id);
	else{
		if (uk_sky_option61 && strcmp(uk_sky_option61, "") != 0)
			op += add_option(op, DHCP_CLIENT_ID, strlen(uk_sky_option61), uk_sky_option61);
		else
			op += add_option(op, DHCP_CLIENT_ID, 7, id);
	}
	op += add_option(op, DHCP_HOST_NAME, strlen(host_name), host_name);
	op += add_option(op, DHCP_VENDOR, sizeof(VENDOR) - 1, VENDOR);
	op += add_option(op, DHCP_PARAM_REQ, sizeof(reqlist), reqlist);
	*op = DHCP_END;

	dhcp_len = sizeof(struct dhcpMessage) -sizeof(dmsg->options) + 3 +
				(op - dmsg->options); /* two bytes padding */
	
	/*********************************************************/
	packet_len = sizeof(struct udphdr) + dhcp_len;
#ifdef Musl_Compile
	packet->udp.uh_sport = htons(CLIENT_PORT);
	packet->udp.uh_dport = htons(SERVER_PORT);
	packet->udp.uh_ulen = htons(packet_len);
	packet->udp.uh_sum = 0; /* zero-csum */
#else
	packet->udp.source = htons(CLIENT_PORT);
	packet->udp.dest = htons(SERVER_PORT);
	packet->udp.len = htons(packet_len);
	packet->udp.check = 0; /* zero-csum */
#endif
	/*********************************************************/
	packet_len += sizeof(struct iphdr);
	packet->ip.version = 4;
	packet->ip.ihl = 5; /* sizeof(struct iphdr) >> 2 */
	packet->ip.tot_len = htons(packet_len);
	packet->ip.ttl = IPDEFTTL;
	packet->ip.protocol = IPPROTO_UDP;
	packet->ip.daddr = 0xFFFFFFFF;
	packet->ip.check = calc_csum(&(packet->ip), sizeof(packet->ip));
	/**********************************************************/
	packet_len += sizeof(struct ether_header);
	memset(packet->eth.ether_dhost, 0xff, 6);
	memcpy(packet->eth.ether_shost, (uint8*)arp, 6);
	packet->eth.ether_type = htons(ETHERTYPE_IP);

	return packet_len;
}

#if 0
#define prtPkt _prtPkt
#else
#define prtPkt(buffer)
#endif

void _prtPkt(uint8 *buffer)
{
	uint8 *ethhead, *iphead;
	FILE *fp;
	ethhead = buffer;

	fp = fopen("/dev/console", "w");
	if (fp < 0)
		perror("fopen");
	fprintf(fp, "Dest MAC address: "
	       "%02x:%02x:%02x:%02x:%02x:%02x\n",
	       ethhead[0],ethhead[1],ethhead[2],
	       ethhead[3],ethhead[4],ethhead[5]);
	fprintf(fp, "Source MAC address: "
	       "%02x:%02x:%02x:%02x:%02x:%02x\n",
	       ethhead[6],ethhead[7],ethhead[8],
	       ethhead[9],ethhead[10],ethhead[11]);
	iphead = buffer+14; /* Skip Ethernet header */
	if (*iphead==0x45) { /* Double check for IPv4
	                      * and no options present */
		fprintf(fp, "Source host %d.%d.%d.%d\n",
	            iphead[12],iphead[13],
	            iphead[14],iphead[15]);
	    fprintf(fp, "Dest host %d.%d.%d.%d\n",
		        iphead[16],iphead[17],
		        iphead[18],iphead[19]);
		fprintf(fp, "Source,Dest ports %d,%d\n",
				(iphead[20]<<8)+iphead[21],
				(iphead[22]<<8)+iphead[23]);
		fprintf(fp, "Layer-4 protocol %d\n",iphead[9]);
	}
	fprintf(fp, "---------------------------------------\n");
	fclose(fp);
}

/* Is it a DHCP-OFFER packet ? */
static int verify_packet(int fd, uint32 xid, uint8 *arp, int *bpain)
{
	int bytes;
	uint8 *opdata, oplen;
	char domain[OPT_SIZE];
	struct rawPacket *packet;
	struct dhcpMessage *dhcp;
	char cmd[128], dnsip[32];
	int code = 0;

	char * p = (char *)malloc(sizeof(struct rawPacket)+1);
	if(!p)
		goto Err;
	bytes = read(fd, p, sizeof(struct rawPacket));
	p[sizeof(struct rawPacket)]='\0';

	packet = (struct rawPacket*)p;
	prtPkt((uint8 *)packet);
	if (bytes < PKTSIZE_NO_OPT + sizeof(struct ether_header)
			|| bytes < ntohs((packet->ip).tot_len) + sizeof(struct ether_header))
		goto Err;

	struct iphdr * ip = &(packet->ip);
#ifndef Musl_Compile
	if (!UDP_IP(ip) ||(packet->udp).dest != htons(CLIENT_PORT))
#else
	if (!UDP_IP(ip) ||(packet->udp).uh_dport != htons(CLIENT_PORT))
#endif
		goto Err;

	dhcp = &(packet->data);
	if (ntohl(dhcp->cookie) != DHCP_MAGIC)
		goto Err;
	if (dhcp->xid != htonl(xid) ||memcmp(dhcp->chaddr, arp, 6))
		goto Err;

	opdata = get_option(dhcp, DHCP_MESSAGE_TYPE, &oplen);
	if (opdata == NULL ||*opdata != DHCPOFFER)
		goto Err;
	
	//**********add for AP mode autodetection function**********//
	if(1==flag_apautodection && get_conf_bool("detwan_apmode_det"))
	{
		// To fix bug 43866 and 43867, we should get the ip address from the bootp protocol but not the ip layer destination ip.
		if(1==count)
		{
			char cmd[256];
			snprintf(cmd, sizeof(cmd),"echo '[AP mode autodetection] first ip address: %u.%u.%u.%u' > /dev/console",dhcp->yiaddr[0],dhcp->yiaddr[1],dhcp->yiaddr[2],dhcp->yiaddr[3]);
			system(str_replace(cmd));
			memcpy(ap_autodection_wanaddress1,dhcp->yiaddr,4);
		}
		else if(2==count)
		{
			char cmd_1[256];
			snprintf(cmd_1, sizeof(cmd_1),"echo '[AP mode autodetection] second ip address: %u.%u.%u.%u' > /dev/console",dhcp->yiaddr[0],dhcp->yiaddr[1],dhcp->yiaddr[2],dhcp->yiaddr[3]);
			system(str_replace(cmd_1));
			memcpy(ap_autodection_wanaddress2,dhcp->yiaddr,4);
		}
		code = 1;
		goto Err;
	}

	opdata = get_option(dhcp, DHCP_DOMAIN_NAME, &oplen);
	if (opdata) {
		snprintf(domain, sizeof(domain), "%.*s", (size_t)oplen, opdata);
		DB("DHCP-Domain : %s\n", domain);
		if (strstr(domain, BPA_SVR_SUFFIX))
			*bpain = 1;
	}

        if ((opdata = get_option(dhcp, DHCP_DNS_SERVER, &oplen)) != NULL) {
                snprintf(dnsip, sizeof(dnsip), "%u.%u.%u.%u", (uint32)*opdata, (uint32)*(opdata+1), (uint32)*(opdata+2), (uint32)*(opdata+3));
                DB("DHCP-DNS-Server : %s\n", dnsip);
                snprintf(cmd, sizeof(cmd), "echo %s > /tmp/detwan-dhcp-dnslist", dnsip);
                system(str_replace(cmd));
	// fix the bug 24774[SQA-93][Smart wizard]Smart Wizard can not detect DHCP mode
	// if there is a DHCP server, we shoud use the dns-server replied by the DHCP server
		snprintf(cmd, sizeof(cmd), "echo nameserver %s > /tmp/resolv.conf", dnsip);
		system(str_replace(cmd));
        }


	code = 1;
Err:
	if(p)
		free(p);
	return code;
}

static int wait_dhcp_offer(int fd, uint32 xid, uint8 *arp, int *bpain)
{
	int r;
	long timeo;
	fd_set readable;
	struct timeval tv;

	timeo = uptime() + DHCP_TIMEOUT;

	for (;;) {
		FD_ZERO(&readable);
		FD_SET(fd, &readable);

		tv.tv_sec = timeo - uptime();
		if (tv.tv_sec <= 0)
			return 0;
		tv.tv_usec = 0;

		r = select(fd + 1, &readable, NULL, NULL, &tv);
		if (r < 1)
			return 0;
		if (verify_packet(fd, xid, arp, bpain))
			return 1;
	}

	return 0;
}

static void set_dst(struct sockaddr *dest, char *ifname)
{
	memset(dest, 0x0, sizeof(struct sockaddr));
	memcpy(dest->sa_data, ifname, sizeof(dest->sa_data));
}

int DHCP_Detection(int *bpain, uint8 *arp)
{
	int i;
	int fd, ret, fond;
	uint32 xid;
	int disc_len;
	struct rawPacket disc;
	struct sockaddr dest;

	*bpain = 0;

	fd = raw_socket();
	if (fd == -1)
		return 0;

	set_dst(&dest, wan_if_name);

	xid = (uint32)uptime() + arp[5];
	disc_len = init_discover(&disc, xid, arp);
	ret = 0;
	fond = 0;
	for (i = 0; i < 3; i++) {
		sendto(fd, &disc, disc_len, 0, (struct sockaddr *) &dest, sizeof(dest));

		ret = wait_dhcp_offer(fd, xid, arp, bpain);
		sleep(2);
		if (ret == 1)
			fond = 1;
	}
	close(fd);	
	return fond;
}

/*======================================================
                                                    [ PPTP Detection ]
    ======================================================*/

static int open_pptpsock(struct in_addr inetaddr) 
{
	int s;
	struct timeval timo;
	struct sockaddr_in dest;

	memset(&dest, 0, sizeof(struct sockaddr_in));
	dest.sin_family = AF_INET;
	dest.sin_port   = htons(PPTP_PORT);
	dest.sin_addr   = inetaddr;

	s = socket(AF_INET, SOCK_STREAM, 0);
	if (s < 0)
		return -1;

	timo.tv_sec = PPTP_TIMEOUT;
	timo.tv_usec = 0;
	setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &timo, sizeof(timo));
	setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &timo, sizeof(timo));
	if (connect(s, (struct sockaddr *) &dest, sizeof(dest)) < 0) {
		close(s); 
		return -1;
	}

	/* Make this socket non-blocking. */
	fcntl(s, F_SETFL, O_NONBLOCK);

	return s;
}

static int wait_ctrl_reply(int fd)
{
	int len;
	fd_set readable;
	struct timeval timo;
	char packet[MAX_PKT_SIZE];
	struct pptp_start_ctrl_conn *repl;

	timo.tv_sec = PPTP_TIMEOUT;
	timo.tv_usec = 0;
	FD_ZERO(&readable);
	FD_SET(fd, &readable);
	if (select(fd + 1, &readable, NULL, NULL, &timo) < 1)
		return 0;

	len = recv(fd, packet, sizeof(packet), 0);
	if (len < sizeof(struct pptp_start_ctrl_conn))
		return 0;

	repl = (struct pptp_start_ctrl_conn *)packet;
	if (repl->header.magic != htonl(PPTP_MAGIC) ||
	    repl->header.pptp_type != htons(PPTP_MESSAGE_CONTROL) ||
	    repl->header.ctrl_type != htons(PPTP_START_CTRL_CONN_RPLY))
		return 0;

	/* This MAY BE a real PPTP server ^_^ */
	return 1;
}

static void init_ctrl_rqst(struct pptp_start_ctrl_conn *req)
{
	memset(req, 0, sizeof(*req));

	req->header.length	= htons(sizeof(*req));
	req->header.pptp_type	= htons(PPTP_MESSAGE_CONTROL);
	req->header.magic		= htonl(PPTP_MAGIC);
	req->header.ctrl_type	= htons(PPTP_START_CTRL_CONN_RQST);

	req->version		= htons(PPTP_VERSION);
	req->framing_cap	= htonl(PPTP_FRAME_CAP);
	req->bearer_cap	= htonl(PPTP_BEARER_CAP);
	req->max_channels= htons(PPTP_MAX_CHANNELS);
	req->firmware_rev	= htons(PPTP_FIRMWARE_VERSION);

	int len = sizeof(req->hostname);
	char * p = (char*)req->hostname;
	strncpy(p, get_conf_string("detwan_pptp_hostname"),len-1);
	p[len-1]='\0';

	len = sizeof(req->vendor);
	p = (char *)req->vendor;
	strncpy(p, PPTP_VENDOR,len-1);
	p[len-1]='\0';
}

static int PPTP_Detection(void)
{
	int i;
	int ret, fd, fond;
	struct in_addr ipaddr;
	struct pptp_start_ctrl_conn req;
	char cmd[128];

#ifdef SUPPORT_SR_CDLESS
	dni_system(NULL, "/usr/sbin/change_wan_ip", get_conf_string("detwan_pptp_ip"), NULL);
#else
	if (!ifconfig(wan_if_name, IF_NONE, get_conf_string("detwan_pptp_ip"),
			get_conf_string("detwan_pptp_netmask")))
		return 0;
#endif

	dni_system(NULL, "/sbin/route", "add", "-net", get_conf_string("detwan_pptp_server"), "netmask", "255.255.255.255", "dev", wan_if_name, NULL);
	char pptp_port[8];
	snprintf(pptp_port, sizeof(pptp_port), "%d", PPTP_PORT);
	dni_system(NULL, "/usr/sbin/iptables", "-t", "mangle", "-I" "PREROUTING", "-i", wan_if_name, "-s", get_conf_string("detwan_pptp_server"), "-d", get_conf_string("detwan_pptp_ip"), "-p", "tcp", "--sport", pptp_port, "-j", "ACCEPT", NULL);
	dni_system(NULL, "/usr/sbin/iptables", "-I" "INPUT", "-i", wan_if_name, "-s", get_conf_string("detwan_pptp_server"), "-d", get_conf_string("detwan_pptp_ip"), "-p", "tcp", "--sport", pptp_port, "-j", "ACCEPT", NULL);

	ret = 0;
	fond = 0;
	ipaddr.s_addr = inet_addr(get_conf_string("detwan_pptp_server"));
	fd = open_pptpsock(ipaddr);
	if (fd < 0) {
#ifdef SUPPORT_SR_CDLESS
		dni_system(NULL, "/usr/sbin/change_wan_ip", "0.0.0.0", NULL);
#else
		ifconfig(wan_if_name, IF_NONE, "0.0.0.0", NULL);
#endif
		return 0; /* or try it again ? */
	}

	init_ctrl_rqst(&req);
	for (i = 0; i < 3; i++) {
		send(fd, &req, sizeof(req), 0);

		ret = wait_ctrl_reply(fd);
		if (ret == 1)
			fond = 1;
	}

	close(fd);
	return fond;
}

/*======================================================
                      [ L2TP Detection ]
======================================================*/
static int open_l2tp_socket(void) 
{
	int s, flags;
	struct sockaddr_in me;

	memset(&me, 0, sizeof(struct sockaddr_in));
	me.sin_family	= AF_INET;
	me.sin_port	= htons(L2TP_PORT);
	me.sin_addr.s_addr = htonl(INADDR_ANY);/*Local Address*/

	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
		return -1;

	if (bind(s, (struct sockaddr *) &me, sizeof(me)) < 0) {
		close(s);
		return -1;
	}

	/* Set socket non-blocking */
	fcntl(s, F_SETFL, O_NONBLOCK);

	return s;
}

int l2tp_add_avp(struct l2tp_dgram *dgram, int mandatory, uint16 len, uint16 type, void *val)
{
	char cmd[128];
	len += 6; /* adjust from payload len to actual len */
	if ((dgram->cursor + len) > dgram->alloc_len)
		return -1;

	dgram->data[dgram->cursor] = (mandatory ? AVP_MANDATORY_BIT : 0); /* no hidden */
	dgram->data[dgram->cursor] |= (len >> 8);
	dgram->data[dgram->cursor+1] = (len & 0xFF);
	dgram->data[dgram->cursor+2] = 0;
	dgram->data[dgram->cursor+3] = 0; /* vendor is always 'VENDOR_IETF == 0' */
	dgram->data[dgram->cursor+4] = (type >> 8);
	dgram->data[dgram->cursor+5] = (type & 0xFF);

	if (len > 6)
		memcpy(dgram->data + dgram->cursor + 6, val, len - 6);

	dgram->cursor += len;
	dgram->payload_len = dgram->cursor;

	return 0;
}

#define ADD_U16AVP(type, val)	do {	\
	u16_val = htons(val);	\
	l2tp_add_avp(&dgram, MANDATORY, sizeof(u16_val), type, &u16_val);	\
} while (0)

#define PUSH_UINT16(buf, cursor, val) \
	do { \
		buf[cursor] = val / 256; \
		buf[cursor + 1] = val & 0xFF; \
		cursor += 2; \
	} while (0)

static void l2tp_dgram_init(struct l2tp_dgram *dgram)
{
	dgram->bits = 0;
	dgram->version = 2;
	dgram->length = 0;
	dgram->tid = 0;
	dgram->sid = 0;
	dgram->Ns = 0;
	dgram->Nr = 0;

	dgram->payload_len = 0;
	dgram->cursor = 0;
	dgram->alloc_len = MAX_PACKET_LEN;
}
void l2tp_new_control(struct l2tp_dgram *dgram, uint16 msg_type, uint16 tid, uint16 sid)
{
	uint16 val;

	l2tp_dgram_init(dgram);

	dgram->bits = TYPE_BIT | LENGTH_BIT | SEQUENCE_BIT;
	dgram->tid = tid;
	dgram->sid = sid;
	dgram->msg_type = msg_type;

	if (msg_type != MESSAGE_ZLB) {
		val = htons(msg_type);

		l2tp_add_avp(dgram, MANDATORY, sizeof(val), AVP_MESSAGE_TYPE, &val);
	}
}
int l2tp_send(int fd, struct l2tp_dgram *dgram)
{
	int cursor = 2;
	socklen_t slen;
	size_t total_len;
	struct sockaddr_in to;
	uint8 *len_ptr = NULL, buf[MAX_PACKET_LEN + 32];
	char cmd[64];
    
	buf[0] = dgram->bits;
	buf[1] = dgram->version;

	if (dgram->bits & LENGTH_BIT) {
		len_ptr = buf + cursor;
		PUSH_UINT16(buf, cursor, dgram->length);
	}

	PUSH_UINT16(buf, cursor, dgram->tid);
	PUSH_UINT16(buf, cursor, dgram->sid);

	if (dgram->bits & SEQUENCE_BIT) {
		PUSH_UINT16(buf, cursor, dgram->Ns);
		PUSH_UINT16(buf, cursor, dgram->Nr);
	}

	total_len = cursor + dgram->payload_len;
	if (dgram->bits & LENGTH_BIT) {
		if(len_ptr){
			*len_ptr++ = total_len / 256;
			*len_ptr = total_len & 255;
		}
	}

	memcpy(buf + cursor, dgram->data, dgram->payload_len);

	slen = sizeof(to);
	memset(&to, 0, sizeof(struct sockaddr_in));
	to.sin_family = AF_INET;
	to.sin_port = htons(L2TP_PORT);
	to.sin_addr.s_addr = inet_addr(get_conf_string("detwan_l2tp_server"));

#ifdef SUPPORT_SR_CDLESS
	dni_system(NULL, "/usr/sbin/change_wan_ip", get_conf_string("detwan_l2tp_ip"), NULL);
#else
	if (!ifconfig(wan_if_name, IF_NONE, get_conf_string("detwan_l2tp_ip"), get_conf_string("detwan_l2tp_netmask"))){
		return 0;
	}
#endif
	dni_system(NULL, "/sbin/route", "add", "-net", get_conf_string("detwan_l2tp_server"), "netmask", "255.255.255.255", "dev", wan_if_name, NULL);
	return sendto(fd, buf, total_len, 0, (struct sockaddr const *)&to, slen);
}
static int tunnel_send_SCCRQ(int fd)
{
	uint16 u16_val, tid;
	uint32 u32_val;
	struct l2tp_dgram *dgram;
	int ret;

	l2tp_new_control(&dgram, MESSAGE_SCCRQ, 0, 0);

	ADD_U16AVP(AVP_PROTOCOL_VERSION, 0x0100);
	tid = (uint16) time(NULL) | 0x0001;
	ADD_U16AVP(AVP_ASSIGNED_TUNNEL_ID, tid);
	ADD_U16AVP(AVP_RECEIVE_WINDOW_SIZE, 4);

	u32_val = htonl(3); /* sync and async */
	l2tp_add_avp(&dgram, MANDATORY, sizeof(u32_val), AVP_FRAMING_CAPABILITIES, &u32_val);
	l2tp_add_avp(&dgram, MANDATORY, (uint16)strlen(L2TP_HOSTNAME), AVP_HOST_NAME, L2TP_HOSTNAME);

	ret = l2tp_send(fd, &dgram);
	return ret;
}

static int l2tp_wait_packet(int fd)
{
	fd_set readable;
	socklen_t slen;
	uint16 vendor, avp_type, msg_type;
	uint8 buf[MAX_PACKET_LEN];
	int r, tries;
	char cmd[128];
	struct timeval tv;
	struct l2tp_dgram dgram;
	struct sockaddr_in from;

	for (;;) {
		tv.tv_sec = L2TP_TIMEOUT;
		tv.tv_usec = 0;

		FD_ZERO(&readable);
		FD_SET(fd, &readable);

		if (select(fd + 1, &readable, NULL, NULL, &tv) < 1)
			return 0; /* Timed out or error happen */
	
		tries = 5;

		memset(&from, 0, sizeof(struct sockaddr_in));
		from.sin_family = AF_INET;
		from.sin_port = htons(L2TP_PORT);
		from.sin_addr.s_addr = inet_addr(get_conf_string("detwan_l2tp_server"));
		slen = sizeof(from);

		while (1) {
			if (--tries <= 0){
				return 0;
			}
			
			r = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *)&from, &slen);
			if (r <= 0)
				return 0;

			/* Check version; drop frame if not L2TP (ver = 2) */
			if ((buf[1] & VERSION_MASK) != 2)
				continue;

			/* A contrl frame -- break out of loop and handle control frame */
			if ((buf[0] & TYPE_BIT))
				break;
		}

		#define L2TP_CHK_BITS	(LENGTH_BIT |SEQUENCE_BIT |OFFSET_BIT)
		#define L2TP_VLD_BITS	(LENGTH_BIT |SEQUENCE_BIT)

		if ((buf[0] & L2TP_CHK_BITS) != L2TP_VLD_BITS)
			return 0;

		vendor = ((uint16)buf[14]) * 256 + (uint16)buf[15];
		avp_type = ((uint16)buf[16]) * 256 + (uint16)buf[17];
		msg_type = ((uint16)buf[18]) * 256 + (uint16)buf[19];

		if (avp_type != AVP_MESSAGE_TYPE || vendor != VENDOR_IETF || msg_type != MESSAGE_SCCRP)	
			return 0;

		return 1;
	}
}

static int L2TP_Detection(void)
{
	int i;
	int sret, ret, fd, fond;
	struct sockaddr_in *peer;
	char cmd[128];
	
	/* Set IPtables Rules */
	char l2tp_port[8];
	snprintf(l2tp_port, sizeof(l2tp_port), "%d", L2TP_PORT);
	dni_system(NULL, "/usr/sbin/iptables", "-t", "mangle", "-I" "PREROUTING", "-i", wan_if_name, "-s", get_conf_string("detwan_l2tp_server"), "-d", get_conf_string("detwan_l2tp_ip"), "-p", "tcp", "--sport", l2tp_port, "-j", "ACCEPT", NULL);
	dni_system(NULL, "/usr/sbin/iptables", "-I" "INPUT", "-i", wan_if_name, "-s", get_conf_string("detwan_l2tp_server"), "-d", get_conf_string("detwan_l2tp_ip"), "-p", "tcp", "--sport", l2tp_port, "-j", "ACCEPT", NULL);

	ret = 0;
	fond = 0;

	fd = open_l2tp_socket();
	if (fd < 0) {
#ifdef SUPPORT_SR_CDLESS
		dni_system(NULL, "/usr/sbin/change_wan_ip", "0.0.0.0", NULL);
#else
		ifconfig(wan_if_name, IF_NONE, "0.0.0.0", NULL);
#endif
		return 0; /* or try it again */
	}

	for (i = 0; i < 3; i++){
		sret = tunnel_send_SCCRQ(fd);
		if( sret < 0){
			continue;
		}
		ret = l2tp_wait_packet(fd);

		if( ret == 1){
			fond = 1;
			break;
		}

	}
	close(fd);
	return fond;
}
/*======================================================
                                         [ Detection WAN Connection Type ]
    ======================================================*/
#define STATUS_DETECTING	9999
#define STATUS_ERROR		10000

#define STATUS_DHCP		10001
#define STATUS_PPPOE	10002
#define STATUS_STATIC	10003
#define STATUS_STATIC_ORNOT	10004
#define STATUS_ALREADY	10005
#define STATUS_BIGPOND	10006
#define STATUS_PPTP		10007
#define STATUS_PLUG_OFF	10008
#define STATUS_INVALID	10009
#define STATUS_L2TP		10010

#define PPPoEFound	(0x1 << 0)
#define DHCPFound	(0x1 << 1)
#define PPTPFound	(0x1 << 2)
#define BPAFound	(0x1 << 3)
#define DHCPSfFound	(0x1 << 4)
#define BPASfFound	(0x1 << 5)
#define L2TPFound  (0x1 << 6)

/*
  * [NETGEAR SPEC V1.6]	4.3 Mac Spoofing:
  * ......
  * [WAN detection phase]:
  * During WAN type detection algorism, if the DHCP detection result is failed when using
  * default MAC address, router should automatically replace to use PC's MAC to send 
  * DHCP Discover messages again.
  * If the DHCP detection result is fine when using by spoofing MAC, router should record
  * the new MAC into flash.
  *
  * [WAN Internet detect sequence]:
  * 1. PPPoE 
  * 2. BPA 
  * 3. PPTP 
  * 4. DHCP 
  * 5. DHCP spoofing 
  * 6. PPTP with spoofing MAC
  * 7. Static IP
  */

int set_promisc(char *ifname)
{
	int sock;
	struct ifreq ethreq;
	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0)
		perror("socket");
	strncpy(ethreq.ifr_name, wan_if_name, IFNAMSIZ);
	if (ioctl(sock, SIOCGIFFLAGS, &ethreq)==-1) {
		perror("ioctl");
		close(sock);
		exit(1);
	}
	ethreq.ifr_flags|=IFF_PROMISC;
	if (ioctl(sock, SIOCSIFFLAGS, &ethreq)==-1) {
		perror("ioctl");
		close(sock);
		exit(1);
	}
	close(sock);

	return 0;
}

int unset_promisc(char *ifname)
{
	int sock;
	struct ifreq ethreq;
	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0)
		perror("socket");
	strncpy(ethreq.ifr_name, wan_if_name, IFNAMSIZ);
	if (ioctl(sock, SIOCGIFFLAGS, &ethreq)==-1) {
		perror("ioctl");
		close(sock);
		exit(1);
	}
	ethreq.ifr_flags &= ~IFF_PROMISC;
	if (ioctl(sock, SIOCSIFFLAGS, &ethreq)==-1) {
		perror("ioctl");
		close(sock);
		exit(1);
	}
	close(sock);

	return 0;
}

void firewall_stop(void)
{
	system("/usr/sbin/firewall.sh stop >/dev/console");
}

void firewall_restart(void)
{
	system("/usr/sbin/firewall.sh restart >/dev/console");
}

uint32_t do_detection(uint8 *dutMac, uint8 *pcMac)
{
	int bpa;
	pid_t pid_dhcp, pid_pppoe, pid_pptp, pid_l2tp, pid_dhcp_sf;
	int ret_dhcp, ret_pppoe, ret_pptp, ret_l2tp, ret_dhcp_sf;
	uint32_t ConnType = 0;
	struct in_addr lan_ipaddr;
	struct in_addr lan_netmask;
	unsigned long lan_subnet;

	/* Set the network card in promiscuos mode */
	set_promisc(wan_if_name);

	/* To fix bug2472[SQA][Setup Wizard][PPTP] When LAN IP address is 10.0.0.1/8, DUT cannot detect WAN port type as PPTP mode
	 * through Setup Wizard.
	 * To clean up the preceding WAN IP while LAN IP is 10.0.0.1/8, it has to stop Firewall. Otherwise DUT will try to
	 * use wan_ipaddr/wan_pptp_local_ip to create a TCP connection with 10.0.0.138 before PPTP Start-Control-Connection-Request,+	     * and return wrong.
	 * */
	lan_ipaddr = get_ipaddr(get_conf_string("detwan_lan_ifname"));
	lan_netmask = get_netmask(get_conf_string("detwan_lan_ifname"));
	lan_subnet = (lan_ipaddr.s_addr) & (lan_netmask.s_addr);
	if((lan_subnet == htonl(0x0a000000))){
		firewall_stop();
        }


	if ((pid_dhcp = fork()) < 0) {
		printf("fork error!\n");
	} else if (pid_dhcp == 0) {	/* Child */
		if (DHCP_Detection(&bpa, dutMac)) {
			if (bpa) {
				exit(BPAFound);
			} else {
				exit(DHCPFound);
			}
		} else {
			exit(0);
		}
	}

	if ((pid_dhcp_sf = fork()) < 0) {
		printf("fork error!");
	} else if (pid_dhcp_sf == 0) {	/* Child */
		if (DHCP_Detection(&bpa, pcMac)) {
			if (bpa) {
				exit(BPASfFound);
			} else {
				exit(DHCPSfFound);
			}
		} else {
			exit(0);
		}
	}

	if ((pid_pptp = fork()) < 0) {
		printf("fork error!\n");
	} else if (pid_pptp == 0) {	/* Child */
		/* PPTP_Detection will set the WAN interface, and the WAN IP will
		 * change to 10.0.0.138 */
		if (PPTP_Detection()) {
			exit(PPTPFound);
		} else {
			exit(0);
		}
	}

	if ((pid_pppoe = fork()) < 0) {
		DB("fork error!\n");
	} else if (pid_pppoe == 0) {
		if (PPPoE_Detection(dutMac)) {
			exit(PPPoEFound);
		} else {
			exit(0);
		}
	}

	if ((pid_l2tp = fork()) < 0) {
		printf("fork error!\n");
	} else if (pid_l2tp == 0) {	/* Child */
		/* L2TP_Detection will set the WAN interface, and the WAN IP will
		 * change to 10.0.0.138 */
		if (L2TP_Detection()) {
			exit(L2TPFound);
		} else {
			exit(0);
		}
	}

	if (waitpid(pid_dhcp, &ret_dhcp, 0) > 0)
		ConnType |= WEXITSTATUS(ret_dhcp);
	if (waitpid(pid_dhcp_sf, &ret_dhcp_sf, 0) > 0)
		ConnType |= WEXITSTATUS(ret_dhcp_sf);
	if (waitpid(pid_l2tp, &ret_l2tp, 0) > 0)
		ConnType |= WEXITSTATUS(ret_l2tp);
	if (waitpid(pid_pptp, &ret_pptp, 0) > 0)
		ConnType |= WEXITSTATUS(ret_pptp);
	if (waitpid(pid_pppoe, &ret_pppoe, 0)> 0)
		ConnType |=  WEXITSTATUS(ret_pppoe);

	/* clear the WAN interface promisc mode */
	unset_promisc(wan_if_name);

	firewall_restart();

	dni_system(NULL, "/sbin/route", "del", "-net", get_conf_string("detwan_pptp_server"), "netmask", "255.255.255.255", "dev", wan_if_name, NULL);
	dni_system(NULL, "/sbin/route", "del", "-net", get_conf_string("detwan_l2tp_server"), "netmask", "255.255.255.255", "dev", wan_if_name, NULL);

#ifdef SUPPORT_SR_CDLESS
	char ctype[8];
	snprintf(ctype, sizeof(ctype), "%d", ConnType);
	dni_system("/tmp/cache/cdless/wan_detect_result", "/bin/echo", ctype, NULL);
#endif
	return ConnType;
}

int Internet_Valid(void)
{
	char *proto;

	if (!eth_up())
		return 0;
		
	proto = get_conf_string("wan_proto");

	if (strcmp(proto, "pppoe") == 0 ||strcmp(proto, "pptp") == 0 || strcmp(proto, "l2tp") == 0)
		return ppp_alive();

	if (strcmp(proto, "dhcp") == 0 ||strcmp(proto, "static") == 0)
		return eth_alive();

	if (strcmp(proto, "bigpond") == 0)
		return bpa_alive();

	return 0;
}

#if ORBI
int Check_IP_Type(void)
{
	if(ap_autodection_wanaddress1[0]==10 || ap_autodection_wanaddress1[0]==192)
	{
		printf("[AP autodetection] The DHCP IP is Private IP\n");
		return 0;
	}
	else if(ap_autodection_wanaddress1[0]==172 && ap_autodection_wanaddress1[1] >=16 && ap_autodection_wanaddress1[1] <=31 )
	{
		printf("[AP autodetection] The DHCP IP is Private IP\n");
		return 0;
	}
	else
	{
		printf("[AP autodetection] The DHCP IP is Public IP\n");
		return 1;
	}
}
#endif
