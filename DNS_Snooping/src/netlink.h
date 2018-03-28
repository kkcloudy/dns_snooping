/*
 * Netlink helper functions for driver wrappers
 * Copyright (c) 2002-2009, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef NETLINK_H
#define NETLINK_H


struct netlink_data;
struct ifinfomsg;

struct netlink_config {
	void *ctx;
	void (*newlink_cb)(void *ctx, struct ifinfomsg *ifi, u8 *buf,
			   size_t len);
	void (*dellink_cb)(void *ctx, struct ifinfomsg *ifi, u8 *buf,
			   size_t len);
};

struct nl_sock
{
        struct sockaddr_nl      s_local;
        struct sockaddr_nl      s_peer;
        int                     s_fd;
        int                     s_proto;
        unsigned int            s_seq_next;
        unsigned int            s_seq_expect;
        int                     s_flags;
        struct nl_cb *          s_cb;
};


enum {
	ARPD_C_UNSPEC,
	ARPD_C_INIT_WAM,
	ARPD_C_INIT_DNSS,
	ARPD_C_FILTER,
	__ARPD_C_MAX
};

#define ARPD_C_MAX (__ARPD_A_MAX - 1)

enum {
	ARPD_A_UNSPEC,
	ARPD_A_ARP_PACKET,
	ARPD_A_DHCP_PACKET,
	ARPD_A_DNS_PACKET,
	__ARPD_A_MAX
};

#define ARPD_A_MAX (__ARPD_A_MAX - 1)


#endif /* NETLINK_H */
