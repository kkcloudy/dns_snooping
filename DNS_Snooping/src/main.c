/*
 * arp-proxy / main()
 * Copyright (c) 2016-2017, Cao Jia
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "includes.h"
#include <sys/wait.h>    
#include <sys/types.h>   
#include <syslog.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <stddef.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/family.h>



#include "common.h"
#include "os.h"
#include "eloop.h"
#include "debug.h"
#include "dns_snooping.h"
#include "dnss_ubus.h"
#include "cache.h"
#include "nmp_process.h"
#include "netlink.h"

/**
 * handle_term - SIGINT and SIGTERM handler to terminate dns snooping process
 */

extern int dnss_debug_level;
#define IPTABLES_LOCK_FILE				"/var/run/eag_iptables_lock"
#define CAP_SHELL_PATH	"/usr/bin/"
#define CAP_SHELL_CMD_LINE_LEN	256
#define NETLINK_DNS 30
extern nmp_mutex_t dns_iptables_lock;
extern char *domain_p[MAX_IPTABLES_LIST];
extern char filter_name[MAX_IPTABLES_LIST][FILTER_NAME_LENTH];
extern char nat_filter_name[MAX_IPTABLES_LIST][FILTER_NAME_LENTH];

struct nl_sock *sock;
int genl_family;


static struct nla_policy arpd_genl_policy[ARPD_A_MAX + 1] = {
        [ARPD_A_UNSPEC]        =       { .type = NLA_UNSPEC },
        [ARPD_A_ARP_PACKET]        =       { .type = NLA_UNSPEC },
        [ARPD_A_DHCP_PACKET]        =       { .type = NLA_UNSPEC },
        [ARPD_A_DNS_PACKET]        =       { .type = NLA_UNSPEC },
};


static void handle_term(int sig, void *signal_ctx)
{
	dnss_printf(DNSS_DEBUG, "Signal %d received - terminating\n", sig);
	eloop_terminate();
}


static void dnss_ctrl_iface_receive(int sock, void *eloop_ctx,
				       void *sock_ctx)
{
	struct dnss_interfaces *dnss_iface = eloop_ctx;
	char buf[512];
	int res;
	struct sockaddr_un from;
	socklen_t fromlen = sizeof(from);
	char *reply;
	const int reply_size = 4096;
	int reply_len;
	char *pos;
	FILE *pf = NULL;
	char cmd[64]={0};

	res = recvfrom(sock, buf, sizeof(buf) - 1, 0,
			   (struct sockaddr *) &from, &fromlen);
	if (res < 0) {
		perror("recvfrom(ctrl_iface)");
		return;
	}
	buf[res] = '\0';

	reply = os_malloc(reply_size);
	if (reply == NULL) {
		sendto(sock, "malloc FAIL\n", 5, 0, (struct sockaddr *) &from,
			   fromlen);
		return;
	}

	os_memcpy(reply, "OK\n", 3);
	reply_len = 3;

	
	
	if(os_memcmp(buf, "LOG_LEVEL", 9) == 0) {
		pos = buf+9;
		if(*pos == '\0') {
			sprintf(reply,"Current Level:%s\n",debug_level_str(dnss_debug_level));
			reply_len = os_strlen(reply);
		} 
		else if(*pos == ' ') {
			pos = buf + 10;
			int level = str_to_debug_level(pos);
			if (level < 0)
				reply_len = -1;
			dnss_debug_level = level;
		}
	}
	else {
		os_memcpy(reply, "UNKNOWN COMMAND\n", 16);
		reply_len = 16;
	}

	if (reply_len < 0) {
		os_memcpy(reply, "FAIL\n", 5);
		reply_len = 5;
	}
	sendto(sock, reply, reply_len, 0, (struct sockaddr *) &from, fromlen);
	os_free(reply);
}


int dnss_global_ctrl_iface_init(struct dnss_interfaces *interfaces)
{
	struct sockaddr_un addr;
	int s = -1;

	interfaces->ctrl_iface_path = os_strdup(DNSS_CTRL_IFACE_PATH);
	if (interfaces->ctrl_iface_path == NULL) {
		dnss_printf(DNSS_DEBUG, "ctrl_iface_path not configured!\n");
		return 0;
	}

	if (mkdir(DNSS_FILE_DIR, S_IRWXU | S_IRWXG) < 0) {
		if (errno == EEXIST) {
			dnss_printf(DNSS_DEBUG, "Using existing control "
				   "interface directory.\n");
		} else {
			perror("mkdir[ctrl_path]");
			goto fail;
		}
	}

	if (os_strlen(interfaces->ctrl_iface_path) >= sizeof(addr.sun_path))
		goto fail;

	s = socket(PF_UNIX, SOCK_DGRAM, 0);
	if (s < 0) {
		perror("socket(PF_UNIX)");
		goto fail;
	}

	os_memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	os_strlcpy(addr.sun_path, interfaces->ctrl_iface_path, sizeof(addr.sun_path));
	if (bind(s, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		dnss_printf(DNSS_DEBUG, "ctrl_iface bind(PF_UNIX) failed: %s\n",
			   strerror(errno));
		if (connect(s, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
			dnss_printf(DNSS_DEBUG, "ctrl_iface exists, but does not"
				   " allow connections - assuming it was left"
				   "over from forced program termination\n");
			if (unlink(interfaces->ctrl_iface_path) < 0) {
				perror("unlink[ctrl_iface]");
				dnss_printf(DNSS_ERROR, "Could not unlink "
					   "existing ctrl_iface socket '%s'\n",
					   interfaces->ctrl_iface_path);
				goto fail;
			}
			if (bind(s, (struct sockaddr *) &addr, sizeof(addr)) <
			    0) {
				perror("bind(PF_UNIX)");
				goto fail;
			}
			dnss_printf(DNSS_DEBUG, "Successfully replaced leftover "
				   "ctrl_iface socket '%s'\n", interfaces->ctrl_iface_path);
		} else {
			dnss_printf(DNSS_INFO, "ctrl_iface exists and seems to "
				   "be in use - cannot override it\n");
			dnss_printf(DNSS_INFO, "Delete '%s' manually if it is "
				   "not used anymore\n", interfaces->ctrl_iface_path);
			os_free(interfaces->ctrl_iface_path);
			interfaces->ctrl_iface_path = NULL;
			goto fail;
		}
	}

	if (chmod(interfaces->ctrl_iface_path, S_IRWXU | S_IRWXG) < 0) {
		perror("chmod[ctrl_interface/ifname]");
		goto fail;
	}
	os_free(interfaces->ctrl_iface_path);

	interfaces->ctrl_iface_sock = s;
	eloop_register_read_sock(s, dnss_ctrl_iface_receive, interfaces, NULL);

	return 0;
fail:
	if (s >= 0)
		close(s);
	if (interfaces->ctrl_iface_path) {
		unlink(interfaces->ctrl_iface_path);
		os_free(interfaces->ctrl_iface_path);
	}
		return -1;
}

void dnss_global_ctrl_iface_deinit(struct dnss_interfaces *interfaces)
{
	char ifname[64] = DNSS_CTRL_IFACE_PATH;

	if(interfaces->ctrl_iface_sock > -1) {
		eloop_unregister_read_sock(interfaces->ctrl_iface_sock);
		close(interfaces->ctrl_iface_sock);
		interfaces->ctrl_iface_sock = -1;
		unlink(ifname);
	}
	
}	

static const char * ipaddr_str(u32 addr)
{
	static char buf[17];

	os_snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
		    (addr >> 24) & 0xff, (addr >> 16) & 0xff,
		    (addr >> 8) & 0xff, addr & 0xff);
	return buf;
}


int send_msg_to_client_behavior(struct dnss_interfaces *inter, DNS_MSG msg)
{
	int ret;
	struct sockaddr_un addr;

	int s = inter->client_behavior_sock;

#ifdef __FreeBSD__
	addr.sun_len = sizeof(addr);
#endif /* __FreeBSD__ */
	addr.sun_family = AF_UNIX;
	os_strlcpy(addr.sun_path, "/var/run/dns_track", sizeof(addr.sun_path));
	
	ret = sendto(s, &msg, sizeof(msg), 0, (struct sockaddr *) &addr, sizeof(addr));
	if(ret < 0){
		dnss_printf(DNSS_ERROR,"send message to client behavior failed\n");
		return -1;
	}
	//dnss_printf(DNSS_DEBUG,"send message to client behavior successful\n");

	return 0;
}


int dns_netlink_packet(struct dnss_interfaces *interf,const u8 *packet,int packet_len)
{
	struct dns_header *header;
	char name[128];
	unsigned char *p,*p1,*endrr;
	
  	int rc, i, j, qtype, qclass, atype, aclass, ttl, rdlen;
  	struct list_addr addr;

	
	int len = packet_len - sizeof(struct iphdr) - sizeof(struct udphdr);
	header = (struct dns_header *)(packet + sizeof(struct iphdr) + sizeof(struct udphdr));

	p = (char *)(header + 1);

	for (i = ntohs(header->qdcount); i != 0; i--) {
		
		int flags = RCODE(header) == NXDOMAIN ? F_NXDOMAIN : 0;
		char tname[128]={0};

		DNS_MSG msg;
		os_memset(&msg, 0, sizeof(msg));

		
		if (!extract_name(header, len, &p, name, 1, 4))
			return 0; /* bad packet */

		strcpy(tname,name);

		GETSHORT(qtype, p); 
      	GETSHORT(qclass, p);
		//dnss_printf(DNSS_DEBUG, "name = %s, qtype = %d, qclass = %d\n",name,qtype,qclass);

		if (qclass != C_IN || qtype == T_PTR)
			continue;

		int addrlen;

		if (qtype == T_A)
	    {
	    	addrlen = INADDRSZ;
	      	flags |= F_IPV4;
	    }
#ifdef HAVE_IPV6
	  	else if (qtype == T_AAAA)
	    {
	   		addrlen = IN6ADDRSZ;
	      	flags |= F_IPV6;
	    }
#endif
	  	else 
	  		continue;

		cname_loop1:
	  	if (!(p1 = skip_questions(header, len)))
	    	return 0;
		
		for (j = 0; j < ntohs(header->ancount); j++) {

			
			int cname_count = CNAME_CHAIN;
			if (!(rc = extract_name(header, len, &p1, name, 0, 10)))
	    		return -1; /* bad packet */	  

			GETSHORT(atype, p1);
	  		GETSHORT(aclass, p1);
	  		GETLONG(ttl, p1);
			GETSHORT(rdlen, p1);
			endrr = p1 + rdlen;

			if (aclass == C_IN && rc != 2 && (atype == T_CNAME || atype == qtype)) {

				if (atype == T_CNAME) {
					if (!cname_count--)
						return 0; /* looped CNAMES */
			
					
					if (!extract_name(header, len, &p1, name, 1, 0))
						return 0;
					//dnss_printf(DNSS_DEBUG, "name = %s\n", name);
		      		goto cname_loop1;
					
				} else {

					if (!CHECK_LEN(header, p1, len, addrlen))
						return 0; /* bad packet */
		      	

					if (flags & F_IPV4) {
						memcpy(&addr.addr4, p1, addrlen);
						in_addr_t ip_addr = ntohl(addr.addr4.s_addr);
						//dnss_printf(DNSS_DEBUG,"name = %s, ip addr = %s\n", tname, ipaddr_str(ip_addr));
						msg.addr[msg.count] = ip_addr;
						msg.count++;
						if(msg.count == MAX_IP_COUNT)
							break;
						
					}
					
				}
				
				 /* bad packet */
			}
			p1 = endrr;
	      	if (!CHECK_LEN(header, p1, len, 0))
				return 0;
		}

		if(msg.count) {
			strcpy(msg.name, tname);
			send_msg_to_client_behavior(interf, msg);
		}
	}
	

	return 0;
}


int client_behavior_sock_init(struct dnss_interfaces *inter)
{
	struct sockaddr_un addr;
	int sock = -1;
	int option = 1;
	char *ifname = NULL;

	ifname = os_strdup(DNSS_CLIENT_BEHAVIOR_PATH);

    if (mkdir(DNSS_FILE_DIR, S_IRWXU | S_IRWXG) < 0) {
		if (errno == EEXIST) {
			dnss_printf(DNSS_DEBUG, "Using existing dnss "
				   "interface directory.");
		} else {
			perror("mkdir[ctrl_interface]");
			goto fail;
		}
	}

    if (os_strlen(ifname) >= sizeof(addr.sun_path))
		goto fail;

	sock = socket(PF_UNIX,SOCK_DGRAM,0);
    if (sock < 0) {
		perror("socket(PF_UNIX)");
		goto fail;
	}
    if(setsockopt(sock,SOL_SOCKET,SO_REUSEADDR,&option,sizeof(option)) < 0){
        dnss_printf(DNSS_DEBUG, "client behavior set reuseaddr failed: %s",
			   strerror(errno));
		goto fail;
	}
	os_memset(&addr, 0, sizeof(addr));
#ifdef __FreeBSD__
	addr.sun_len = sizeof(addr);
#endif /* __FreeBSD__ */
	addr.sun_family = AF_UNIX;

	os_strlcpy(addr.sun_path, ifname, sizeof(addr.sun_path));
	unlink(ifname);
	if(bind(sock,(struct sockaddr *)&addr,sizeof(addr)) < 0){
        dnss_printf(DNSS_DEBUG, "dnss client behavior bind(PF_UNIX) failed: %s",
			   strerror(errno));
		goto fail;
	}
	if (chmod(ifname, S_IRWXU | S_IRWXG) < 0) {
		perror("chmod[dnss_interface/ifname]");
		goto fail;
	}
	os_free(ifname);

	inter->client_behavior_sock = sock;
	
	dnss_printf(DNSS_DEBUG, "Setup dnss client behavior successful!");

	return 0;

fail:
	if (sock >= 0)
		close(sock);
	if (ifname) {
		unlink(ifname);
		os_free(ifname);
	}
	return -1;
	
}

void client_behavior_sock_deinit(struct dnss_interfaces *inter)
{
	char ifname[64] = DNSS_CLIENT_BEHAVIOR_PATH;

	if(inter->client_behavior_sock > -1) {
		eloop_unregister_read_sock(inter->client_behavior_sock);
		close(inter->client_behavior_sock);
		inter->client_behavior_sock = -1;
		unlink(ifname);
	}
}



static int dns_iptables_init(void)
{
	int ret;
	char cmd[CAP_SHELL_CMD_LINE_LEN] = {0};
	snprintf( cmd, sizeof(cmd),CAP_SHELL_PATH"dns_cp_default.sh");
	ret = system(cmd);
	ret = WEXITSTATUS(ret);
	dnss_printf(DNSS_INFO,"captive_shell_default  %s ret=%d\n", cmd, ret);
	return ret;
}

static int dns_iptables_destroy(void)
{
	int ret;
	char cmd[CAP_SHELL_CMD_LINE_LEN] = {0};
	snprintf( cmd, sizeof(cmd),CAP_SHELL_PATH"dns_cp_del_rules.sh");
	ret = system(cmd);
	ret = WEXITSTATUS(ret);
	dnss_printf(DNSS_INFO,"captive_shell_default  %s ret=%d\n", cmd, ret);
	return ret;
}

static int dns_destroy_global_chain()
{
	int ret;
	int i;
	char cmd[CAP_SHELL_CMD_LINE_LEN] = {0};
	for(i=0; i<MAX_IPTABLES_LIST; i++)
	{
		if(NULL != domain_p[i])
		{
			dnss_printf(DNSS_DEBUG,"free sucess %s\n",domain_p[i]);
			free(domain_p[i]);
			domain_p[i]=NULL;
		}
	}
	return ret;
}

static int dns_filter_init(void)
{
	int i;
	for(i=0; i<MAX_IPTABLES_LIST; i++)
	{
		snprintf(filter_name[i],FILTER_NAME_LENTH,"CP_domain_%d",i);	
		snprintf(nat_filter_name[i],FILTER_NAME_LENTH,"DNSS_DNAT_%d",i);
	}
	return 0;
}

void genl_rcv_msg(int socket, void *eloop_ctx,void *sock_ctx)
{
	nl_recvmsgs_default(sock);
}

int parse_cb(struct nl_msg *msg, void *arg)
{
	struct dnss_interfaces *inter = arg;
	struct nlmsghdr *nlh = nlmsg_hdr(msg);
    struct genlmsghdr *gnlh = nlmsg_data(nlh);
	struct nlattr *attrs[ARPD_A_MAX + 1];
	char skb_buf[4096];
	int len;

	dnss_printf(DNSS_DEBUG,"receive genl msg, cmd = %d\n",gnlh->cmd);

	genlmsg_parse(nlh, 0, attrs, ARPD_A_MAX, arpd_genl_policy);

	switch (gnlh->cmd){
		
    	case ARPD_C_FILTER:
					
        	if (attrs[ARPD_A_DNS_PACKET]){

				dnss_printf(DNSS_DEBUG, "Got a dns packet from kernel\n");
                memset(skb_buf, 0, sizeof(skb_buf));
				len = nla_len(attrs[ARPD_A_DNS_PACKET]);
                memcpy(skb_buf, nla_data(attrs[ARPD_A_DNS_PACKET]), len);
                dns_netlink_packet(inter, skb_buf, len);
            }

           	return NL_OK;
       	default:
            return NL_SKIP;
        }
}

int dnss_genl_init(struct dnss_interfaces *inter)
{
	int ret;
	struct nl_msg *msg;
	
	sock = nl_socket_alloc();
	
	if(sock == NULL)
	{
		dnss_printf(DNSS_ERROR,"Unable to allocate socket");
		return -1;
	}

	ret = genl_connect(sock);

	if(ret < 0)
	{
		dnss_printf(DNSS_ERROR,"genl sock connect failed");
		return -1;
	}

	genl_family = genl_ctrl_resolve(sock, "ARPD");

	if(genl_family < 0)
	{
		dnss_printf(DNSS_ERROR, "Unable to resolve family");
		nl_close(sock);
        nl_socket_free(sock);
        return -1;
    }

	dnss_printf(DNSS_ERROR, "generic netlink family:[%d]", genl_family);

	nl_socket_disable_seq_check(sock);
    nl_socket_modify_cb(sock, NL_CB_VALID, NL_CB_CUSTOM, parse_cb, inter);

	msg = nlmsg_alloc();
    if (msg == NULL)
	{
                dnss_printf(DNSS_ERROR, "Unable to allocate message");
                return -1;
    }

	
	genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, genl_family, 0,
					0, ARPD_C_INIT_DNSS, 0);

	ret = nl_send_auto_complete(sock, msg);
    nlmsg_free(msg);
    if (ret < 0)
	{
     	dnss_printf(DNSS_ERROR, "nl_send_auto_complete failed");
        return ret;
    }

	dnss_printf(DNSS_INFO, "nl_send_auto_complete success,ret = %d",ret);

	eloop_register_read_sock(sock->s_fd, genl_rcv_msg, NULL, NULL);
	return 0;
}

void dnss_genl_deinit(void)
{
	nl_close(sock);
    nl_socket_free(sock);
}

int dnss_global_init(struct dnss_interfaces *interfaces)
{
	if (eloop_init()) {
		dnss_printf(DNSS_ERROR, "Failed to initialize event loop\n");
		return -1;
	}
	eloop_register_signal_terminate(handle_term, interfaces);

	cache_hash_init(CACHESIZ);
	(void)dnss_ubus_init(interfaces);
	(void)dns_init_list();
	 dns_iptables_destroy();
	 dns_destroy_global_chain();
	 dns_iptables_init();
	 dns_module_restart();
	 dns_read_walled_garden_config();
	 dns_filter_init();
	if (dnss_global_ctrl_iface_init(interfaces)){
		dnss_printf(DNSS_ERROR, "Failed to setup control interface\n");
		return -1;
	}

	if (dnss_nfqueue_iface_init(interfaces)){
		dnss_printf(DNSS_ERROR, "Failed to setup database interface\n");
		return -1;
	}

	if(dnss_genl_init(interfaces)){
		dnss_printf(DNSS_ERROR,"Failed to setup generic netlink interface\n");
		return -1;
	}
	client_behavior_sock_init(interfaces);
	return 0;
}

static int dnss_global_run(struct dnss_interfaces *ifaces, int daemonize,
			      const char *pid_file)
{

	eloop_run();

	return 0;
}


int main(int argc, char *argv[])
{
	struct dnss_interfaces interfaces;
	int ret = 0, daemonize = 1;
	char *pid_file = NULL;

	dnss_iface = &interfaces;
	interfaces.ctrl_iface_path = NULL;
	interfaces.ctrl_iface_sock = 0;
	interfaces.nfq_sock = 0;
	interfaces.h = NULL;
	interfaces.qh = NULL;

	
	ret = dnss_debug_open_file(DNSS_OUT_FILE);
	nmp_mutex_init(&dns_iptables_lock, IPTABLES_LOCK_FILE);
	if (dnss_global_init(&interfaces)){
		dnss_printf(DNSS_DEBUG, "dnss global init failed.\n");
		goto out;
	}
	pid_file = os_strdup(DNSS_PID_FILE);
	if (dnss_global_run(&interfaces, daemonize, pid_file))
		goto out;
out:
	nmp_mutex_destroy(&dns_iptables_lock);
	dns_profile_list_destroy();
	dns_iptables_destroy();
	dns_destroy_global_chain();
	dnss_ubus_fini(&interfaces);
	dnss_global_ctrl_iface_deinit(&interfaces);
	dnss_genl_deinit();
	client_behavior_sock_deinit(&interfaces);
	dnss_nfqueue_iface_deinit(&interfaces);
	return 0;
}
