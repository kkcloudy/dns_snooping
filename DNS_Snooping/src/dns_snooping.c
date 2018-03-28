/*
 * arp-proxy
 * Copyright (c) 2016-2017, Cao Jia
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "includes.h"
#include <syslog.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <stddef.h>
#include <sys/wait.h>

#include <net/if.h>
#include <sys/ioctl.h>

#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>

#include <linux/netlink.h>
#include <netinet/in.h>

#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#include "common.h"
#include "eloop.h"
#include "debug.h"
#include "dns_snooping.h"
#include "dnss_ubus.h"

#include "list.h"
#include "cache.h"
#include "dns_iptables.h"


extern struct dns_profile *gloable_agm_profle;
extern char *domain_p[MAX_IPTABLES_LIST];


void printPacketBuffer(unsigned char *buffer,unsigned long buffLen)
{
        unsigned int i;

        if(!buffer)
                return;
        dnss_printf(DNSS_DEBUG, ":::::::::::::::::::::::::::::::::::::::::::::::\n");

        for(i = 0;i < buffLen ; i++)
        {
                dnss_printf(DNSS_DEBUG, "%02x ",buffer[i]);
                if(0==(i+1)%16) {
                        dnss_printf(DNSS_DEBUG, "\n");
                }
        }
        if((buffLen%16)!=0)
        {
                dnss_printf(DNSS_DEBUG, "\n");
        }
        dnss_printf(DNSS_DEBUG, ":::::::::::::::::::::::::::::::::::::::::::::::\n");
}

static const char * ipaddr_str(u32 addr)
{
	static char buf[17];

	os_snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
		    (addr >> 24) & 0xff, (addr >> 16) & 0xff,
		    (addr >> 8) & 0xff, addr & 0xff);
	return buf;
}


int check_name(char *name)
{

	int i;
	for(i=0;i<MAX_IPTABLES_LIST;i++)
	{
		if(NULL != domain_p[i])
		{
			if(0 == os_strcmp(name,domain_p[i]))
				return 0;
		}
	}
	return 1;
}

static int handle_nfqueue_dns(struct dns_header *header, int plen)
{
	unsigned char *psave, * p1, *p, *endrr;
  	struct crec *crecp, *recp1;
  	int rc, i, j, qtype, qclass, atype, aclass, ttl, rdlen;
	struct list_addr addr;

	if(gloable_agm_profle == NULL) {
		dnss_printf(DNSS_INFO,"gloable_agm_profle is NULL!\n");
		return 0;
	}
	
	time_t now;
	char name[128];


	p = (unsigned char *)(header+1);
	
	//printPacketBuffer(p, plen-sizeof(struct dns_header));

	now = dnsmasq_time();
	
	for (i = ntohs(header->qdcount); i != 0; i--) {

		int cname_count = CNAME_CHAIN;
		int flags = RCODE(header) == NXDOMAIN ? F_NXDOMAIN : 0;
		int name_id;
		char tname[128]={0};
		if (!extract_name(header, plen, &p, name, 1, 4))
			return 0; /* bad packet */

        if(check_name(name)){
			//dnss_printf(DNSS_DEBUG,"can not find name:%s in config file\n",name);
			return 0;
        }
		
		strcpy(tname,name);

      	GETSHORT(qtype, p); 
      	GETSHORT(qclass, p);
		dnss_printf(DNSS_DEBUG, "name = %s, qtype = %d, qclass = %d\n",name,qtype,qclass);

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
	  	if (!(p1 = skip_questions(header, plen)))
	    	return 0;
		
		for (j = 0; j < ntohs(header->ancount); j++) {

			
			
			if (!(rc = extract_name(header, plen, &p1, name, 0, 10)))
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
				
					if (!extract_name(header, plen, &p1, name, 1, 0))
						return 0;
					dnss_printf(DNSS_DEBUG, "name = %s\n", name);
		      		goto cname_loop1;
					
				} else {

					if (!CHECK_LEN(header, p1, plen, addrlen))
						return 0; /* bad packet */
			
					if(addrlen == INADDRSZ)
					{
						memcpy(&addr.addr4, p1, addrlen);
						addr.addr4.s_addr = ntohl(addr.addr4.s_addr);
						
					}
			#ifdef HAVE_IPV6
					else
					{
						memcpy(&addr.addr6, p1, addrlen);
					}
			#endif
					cache_insert(tname, &addr, now, ttl, flags);		
				}
				
				 /* bad packet */
			}
			p1 = endrr;
	      	if (!CHECK_LEN(header, p1, plen, 0))
				return 0;
		}
	}

	return 0;
}


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi; 
	int ret;
	unsigned char *dnsdata, *tmp;
	struct ethhdr *ethh;

	dnss_printf(DNSS_DEBUG, "entering callback\n");

	dnsdata = (char *)os_malloc(PACKETSZ);
	if(dnsdata == NULL) {
		dnss_printf(DNSS_ERROR,"malloc dnsdata failde\n");
		return -1;
	}
	os_memset(dnsdata, 0, PACKETSZ);
	
	ph = nfq_get_msg_packet_hdr(nfa);
	if (ph) {
		id = ntohl(ph->packet_id);
		dnss_printf(DNSS_DEBUG, "hw_protocol=0x%04x hook=%u id=%u ",
			ntohs(ph->hw_protocol), ph->hook, id);
	}

	hwph = nfq_get_packet_hw(nfa);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

		dnss_printf(DNSS_DEBUG, "hw_src_addr=");
		for (i = 0; i < hlen-1; i++)
			dnss_printf(DNSS_DEBUG, "%02x:", hwph->hw_addr[i]);
		dnss_printf(DNSS_DEBUG, "%02x ", hwph->hw_addr[hlen-1]);
	}

	ifi = nfq_get_indev(nfa);
	if (ifi)
		dnss_printf(DNSS_DEBUG, "indev=%u ", ifi);



	ret = nfq_get_payload(nfa, &tmp);

	if (ret >= 0)
		dnss_printf(DNSS_DEBUG, "payload_len=%d ", ret);

	//dnss_printf(DNSS_DEBUG, "payload:\n");
	//printPacketBuffer(tmp, ret);

	os_memcpy(dnsdata, tmp, ret);
	
	dnsdata +=sizeof(struct iphdr);
	dnsdata +=sizeof(struct udphdr);
	ret -=sizeof(struct iphdr);
	ret -=sizeof(struct udphdr);
	handle_nfqueue_dns((struct dns_header *)dnsdata, ret); 
	nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

	return 0;
	
}


int linux_br_get(char *brname, const char *ifname)
{
	char path[128], brlink[128], *pos;
	os_snprintf(path, sizeof(path), "/sys/class/net/%s/brport/bridge",
		    ifname);
	os_memset(brlink, 0, sizeof(brlink));
	if (readlink(path, brlink, sizeof(brlink) - 1) < 0)
		return -1;
	pos = os_strrchr(brlink, '/');
	if (pos == NULL)
		return -1;
	pos++;
	os_strlcpy(brname, pos, IFNAMSIZ);
	return 0;
}



static void dnss_nfqueue_receive(int sock, void *eloop_ctx,
				       void *sock_ctx)
{
    int res;
    char buf[4096] __attribute__ ((aligned));
	struct dnss_interfaces *dnss_iface = eloop_ctx;

    /* recv msg from kernel */
    res = recv(dnss_iface->nfq_sock, buf, sizeof(buf), 0);
    if (res < 0) {
		if (errno == ENOBUFS) {
			dnss_printf(DNSS_DEBUG, "recv(nfqueue):losing packets!\n");
			return;
		} else {
			dnss_printf(DNSS_ERROR, "recv(nfqueue):recv failed!\n");
			goto fail;
		}
	}

	dnss_printf(DNSS_DEBUG, "pkt received\n");
	nfq_handle_packet(dnss_iface->h, buf, res);

    return;
	
fail:
	dnss_printf(DNSS_DEBUG, "unbinding from queue 0\n");
	nfq_destroy_queue(dnss_iface->qh);
	
#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	dnss_printf(DNSS_DEBUG, "unbinding from AF_INET\n");
	nfq_unbind_pf(dnss_iface->h, AF_INET);
#endif

	dnss_printf(DNSS_DEBUG, "closing library handle\n");
	nfq_close(dnss_iface->h);

	return;
}

int dnss_nfqueue_iface_init(struct dnss_interfaces *interfaces)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	int fd;
	int rv;

	dnss_printf(DNSS_DEBUG, "opening library handle\n");
	h = nfq_open();
	if (!h) {
		dnss_printf(DNSS_ERROR, "error during nfq_open()\n");
		goto fail_open;
	}

	dnss_printf(DNSS_DEBUG, "unbinding existing nf_queue handler for NFPROTO_ARP (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		dnss_printf(DNSS_ERROR, "error during nfq_unbind_pf()\n");
		goto fail_open;
	}

	dnss_printf(DNSS_DEBUG, "binding nfnetlink_queue as nf_queue handler for NFPROTO_ARP\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		dnss_printf(DNSS_ERROR, "error during nfq_bind_pf()\n");
		goto fail_bind;
	}

	dnss_printf(DNSS_DEBUG, "binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  1000, &cb, NULL);
	if (!qh) {
		dnss_printf(DNSS_ERROR, "error during nfq_create_queue()\n");
		goto fail_create;
	}
	
	dnss_printf(DNSS_DEBUG, "setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		dnss_printf(DNSS_ERROR, "can't set packet_copy mode\n");
		goto fail_create;
	}
	fd = nfq_fd(h);
	interfaces->nfq_sock = fd;
	interfaces->h = h;
	interfaces->qh = qh;
	
	eloop_register_read_sock(fd, dnss_nfqueue_receive, interfaces, NULL);

	return 0;
	
fail_create:
	dnss_printf(DNSS_DEBUG, "unbinding from queue 0\n");
	if (qh)
		nfq_destroy_queue(qh);
fail_bind:
	dnss_printf(DNSS_DEBUG, "unbinding from NFPROTO_ARP\n");
	nfq_unbind_pf(h, NFPROTO_ARP);
fail_open:
	dnss_printf(DNSS_DEBUG, "closing library handle\n");
	if (h)
		nfq_close(h);

	return -1;
	
}

void dnss_nfqueue_iface_deinit(struct dnss_interfaces *interfaces)
{
	if(interfaces->qh)
		nfq_destroy_queue(interfaces->qh);

	if(interfaces->h)
		nfq_close(interfaces->h);

	if(interfaces->nfq_sock)
		close(interfaces->nfq_sock);
}


/* The rtrim() function removes trailing spaces from a string. */
char *rtrim(char *str)
{
        int n = strlen(str) - 1;
	while((*(str + n) == ' ') ||(*(str + n) == '\n') ||(*(str + n) == '\r'))
	{
                *(str+n--) = '\0';
	}
}

