/*
 * dns_snooping / Initialization and configuration
 * Copyright (c) 2016-2017, Cao Jia
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */
#ifndef DNS_SNOOPING_H
#define DNS_SNOOPING_H
#include "dnss_ubus.h"
#include "cache.h"

#define DNSS_OUT_FILE "/tmp/log/dns_snooping.log"
#define DNSS_PID_FILE "/var/run/dnss/dnss.pid"

#define DNSS_FILE_DIR "/var/run/dnss/"
#define DNSS_CTRL_IFACE_PATH "/var/run/dnss/dnss_ctrl"
#define DNSS_CLIENT_BEHAVIOR_PATH "/var/run/dnss/client_behavior"


#define MAX_PAYLOAD 1024

struct dnss_interfaces {
	char *ctrl_iface_path;
	int ctrl_iface_sock;
	int nfq_sock;
	int ioctl_sock;
	int netlink_sock;
	int client_behavior_sock;
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct ubus_object ubus_obj;
};

struct dnss_interfaces *dnss_iface;

typedef struct {
	char name[128];
	int count;
	in_addr_t addr[MAX_IP_COUNT];
} DNS_MSG;


void printPacketBuffer(unsigned char *buffer,unsigned long buffLen);
int linux_br_get(char *brname, const char *ifname);

int dnss_nfqueue_iface_init(struct dnss_interfaces *interfaces);
void dnss_nfqueue_iface_deinit(struct dnss_interfaces *interfaces);



#endif
