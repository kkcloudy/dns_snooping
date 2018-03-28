#ifndef CACHE_H
#define CACHE_H

#include "dns-protocol.h"
#include <sys/types.h> 
#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <ctype.h>
#include <signal.h>
#include <stddef.h>
#include <time.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>
#include <stdarg.h>


#define CACHESIZ 1024 /* default cache size */
#define SMALLDNAME 50 
#define CNAME_CHAIN 10 /* chains longer than this atr dropped for loop protection */
#define IFACENAME 32
#define MAX_IP_COUNT 32

struct list_addr {
	struct in_addr addr4;
#ifdef HAVE_IPV6
    struct in6_addr addr6;
#endif
	time_t ttd;
	struct list_addr *next;
};


struct cache {
	struct cache *next, *prev, *hnext;
	union {
    	char sname[SMALLDNAME];
    	char *bname;
  	} name;
	
	struct list_addr *addr;
	unsigned short ip_count; 
	unsigned short flag;  
};

#define F_IMMORTAL  (1u<<0)
#define F_NAMEP     (1u<<1)
#define F_REVERSE   (1u<<2)
#define F_FORWARD   (1u<<3)
#define F_DHCP      (1u<<4)
#define F_NEG       (1u<<5)       
#define F_HOSTS     (1u<<6)
#define F_IPV4      (1u<<7)
#define F_IPV6      (1u<<8)
#define F_BIGNAME   (1u<<9)
#define F_NXDOMAIN  (1u<<10)
#define F_CNAME     (1u<<11)
#define F_DNSKEY    (1u<<12)
#define F_CONFIG    (1u<<13)
#define F_DS        (1u<<14)
#define F_DNSSECOK  (1u<<15)


#define T_A		1
#define T_NS            2
#define T_MD            3
#define T_MF            4             
#define T_CNAME		5
#define T_SOA		6
#define T_MB            7
#define T_MG            8
#define T_MR            9
#define T_PTR		12
#define T_MINFO         14
#define T_MX		15
#define T_TXT		16
#define T_RP            17
#define T_AFSDB         18
#define T_RT            21
#define T_SIG		24
#define T_PX            26
#define T_AAAA		28
#define T_NXT           30
#define T_SRV		33
#define T_NAPTR		35
#define T_KX            36
#define T_DNAME         39
#define T_OPT		41
#define T_DS            43
#define T_RRSIG         46
#define T_NSEC          47
#define T_DNSKEY        48
#define T_NSEC3         50
#define	T_TKEY		249		
#define	T_TSIG		250
#define T_AXFR          252
#define T_MAILB		253	
#define T_ANY		255

/* util.c */

int legal_hostname(char *name);

unsigned char *do_rfc1035_name(unsigned char *p, char *sval, char *limit);
void *safe_malloc(size_t size);
void safe_pipe(int *fd, int read_noblock);
int hostname_isequal(const char *a, const char *b);
time_t dnsmasq_time(void);
int netmask_length(struct in_addr mask);
int is_same_net(struct in_addr a, struct in_addr b, struct in_addr mask);
#ifdef HAVE_IPV6
int is_same_net6(struct in6_addr *a, struct in6_addr *b, int prefixlen);
u64 addr6part(struct in6_addr *addr);
void setaddr6part(struct in6_addr *addr, u64 host);
#endif

int extract_name(struct dns_header *header, size_t plen, unsigned char **pp, 
		 char *name, int isExtract, int extrabytes);
unsigned char *skip_name(unsigned char *ansp, struct dns_header *header, size_t plen, int extrabytes);
unsigned char *skip_questions(struct dns_header *header, size_t plen);
unsigned char *skip_section(unsigned char *ansp, int count, struct dns_header *header, size_t plen);
int cache_insert(char *name, struct list_addr *addr, 
			time_t now,  unsigned long ttl, unsigned short flags);
void cache_hash_init(int size);
void cache_printf(void);
void cache_delete(char *name);
void tail_delete(void);





#endif
