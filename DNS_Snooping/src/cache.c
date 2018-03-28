#include <time.h>
#include "cache.h"
#include "common.h"
#include "debug.h"
#include "dnss_ubus.h"
#include "dns_iptables.h"

static struct cache *cache_list = NULL, *cache_tail = NULL, **cache_hash = NULL;
static int cache_hash_size, cache_list_size;


static const char * ipaddr_str(u32 addr)
{
	static char buf[17];

	os_snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
		    (addr >> 24) & 0xff, (addr >> 16) & 0xff,
		    (addr >> 8) & 0xff, addr & 0xff);
	return buf;
}

static const struct {
  unsigned int type;
  const char * const name;
} typestr[] = {
  { 1,   "A" },
  { 2,   "NS" },
  { 5,   "CNAME" },
  { 6,   "SOA" },
  { 10,  "NULL" },
  { 11,  "WKS" },
  { 12,  "PTR" },
  { 13,  "HINFO" },	
  { 15,  "MX" },
  { 16,  "TXT" },
  { 22,  "NSAP" },
  { 23,  "NSAP_PTR" },
  { 24,  "SIG" },
  { 25,  "KEY" },
  { 28,  "AAAA" },
  { 33,  "SRV" },
  { 35,  "NAPTR" },
  { 36,  "KX" },
  { 37,  "CERT" },
  { 38,  "A6" },
  { 39,  "DNAME" },
  { 41,  "OPT" },
  { 43,  "DS" },
  { 46,  "RRSIG" },
  { 47,  "NSEC" },
  { 48,  "DNSKEY" },
  { 50,  "NSEC3" },
  { 249, "TKEY" },
  { 250, "TSIG" },
  { 251, "IXFR" },
  { 252, "AXFR" },
  { 253, "MAILB" },
  { 254, "MAILA" },
  { 255, "ANY" }
};

char *cache_get_tname(struct cache *cache)
{
	if(cache->flag & F_BIGNAME)
		return cache->name.bname;
	else
		return cache->name.sname;
}

static struct cache **new_hash_bucket(char *name)
{
	unsigned int c, val = 017465; /* Barker code - minimum self-correlation in cyclic shift */
  	const unsigned char *mix_tab = (const unsigned char*)typestr; 

	while((c = (unsigned char) *name++))
    {
      /* don't use tolower and friends here - they may be messed up by LOCALE */
    	if (c >= 'A' && c <= 'Z')
		c += 'a' - 'A';
      	val = ((val << 7) | (val >> (32 - 7))) + (mix_tab[(val + c) & 0x3F] ^ c);
    } 
  
  /* hash_size is a power of two */
  return cache_hash + ((val ^ (val >> 16)) & (cache_hash_size - 1));
}



void cache_hash_init(int size)
{
	int new_size;
	for (new_size = 64; new_size < size/10; new_size = new_size << 1);
	cache_hash_size = new_size;

	if(!cache_hash) {
		cache_hash = safe_malloc(new_size * sizeof(struct cache*));
	}
}

void cache_hash_deinit(void)
{

}

int add_iptables_rule(char *name, u32 addr)
{
	int domain_id = dns_get_domain_id(name);

	if(connect_up(addr, domain_id))
	{
		dnss_printf(DNSS_DEBUG,
			"add iptables rule name:%s,ip:%s failed!\n",name,ipaddr_str(addr));
		return -1;
	}
	
	return 0;
}
struct cache *new_cache_malloc(char *name, struct list_addr *addr, 
			time_t now,  unsigned long ttl, unsigned short flags)
{
	struct cache *tmp =(struct cache *)safe_malloc(sizeof(struct cache));

	if(tmp == NULL)
	{
		dnss_printf(DNSS_DEBUG,"malloc new cache entry failed!\n");
		return NULL;
	}

	if (name && (strlen(name) > SMALLDNAME-1)) 
	{
		tmp->flag |= F_BIGNAME;
		tmp->name.bname = (char *)safe_malloc(MAXDNAME);

		if(tmp->name.bname == NULL)
		{
			dnss_printf(DNSS_DEBUG, "malloc bname failed!\n");
			free(tmp);
			return NULL;
		}
		strcpy(tmp->name.bname, name);
	} 
	else
	{
		strcpy(tmp->name.sname, name);
	}

	struct list_addr *taddr = (struct list_addr *)safe_malloc(sizeof(struct list_addr));

	if(taddr == NULL)
	{
		dnss_printf(DNSS_DEBUG,"malloc list_addr failed!\n");

		if(tmp->flag & F_BIGNAME)
			free(tmp->name.bname);
		free(tmp);
		return NULL;
	}

	if(flags & F_IPV4) {
		os_memcpy(&taddr->addr4, &addr->addr4, INADDRSZ);
		tmp->flag |= F_IPV4;
		add_iptables_rule(name, taddr->addr4.s_addr);
	}
#ifdef HAVE_IPV6
	else
	{
		os_memcpy(&taddr->addr6, &addr->addr6, IN6ADDRSZ);
		tmp->flag |= F_IPV6;
	}
#endif
	tmp->addr = taddr;
	tmp->ip_count++;

	return tmp;
}
	
int cache_insert(char *name, struct list_addr* addr, 
			time_t now,  unsigned long ttl, unsigned short flags)
{
	struct cache *tmp;
	struct cache **up;
	int found = 0;
	int old  = 0; 

	for(up = new_hash_bucket(name),tmp = *up; tmp; tmp = tmp->hnext)
	{
		if(hostname_isequal(name, cache_get_tname(tmp)) && (flags | tmp->flag ))
		{
			dnss_printf(DNSS_INFO,"find an old cache entry,name = %s!\n",name);
			found = 1;	
	#ifdef HAVE_IPV6
      		int addrlen = (flags & F_IPV6) ? IN6ADDRSZ : INADDRSZ;
	#else
      		int addrlen = INADDRSZ;
	#endif 
			struct list_addr *taddr = tmp->addr;
			while(taddr) 
			{

				if( (flags & F_IPV4) && (memcmp(&addr->addr4, &taddr->addr4, addrlen) == 0))
				{
					dnss_printf(DNSS_INFO,"ip:%s has exist in cache list!\n",ipaddr_str(addr->addr4.s_addr));
					old = 1;
					break;
				}
	#ifdef HAVE_IPV6
				if( (flags & F_IPV6) && (memcmp(&addr->addr6, &taddr->addr6, addrlen) == 0))
				{
					dnss_printf(DNSS_DEBUG,"ipv6 addr has exist in cache list!\n");
					old = 1;
					break;
				}
	#endif			
				taddr = taddr->next;
			}

			if(old == 0)
			{
				if(tmp->ip_count > MAX_IP_COUNT)
				{
					/* TODO:remove old ipaddr */
					return -1;
				}
				else
				{
					dnss_printf(DNSS_DEBUG,"try to add a new addr!\n");
					struct list_addr *taddr = (struct list_addr *)safe_malloc(sizeof(struct list_addr));

					if(addr == NULL)
					{
						dnss_printf(DNSS_DEBUG,"malloc list_addr failed!\n");
						return -1;
					}

					if(flags | F_IPV4) 
					{
						os_memcpy(&taddr->addr4, &addr->addr4, INADDRSZ);
						add_iptables_rule(name, taddr->addr4.s_addr);
					}
			#ifdef HAVE_IPV6
					else
						os_memcpy(&taddr->addr6, &addr->addr6, IN6ADDRSZ);
			#endif
					taddr->next = tmp->addr;
					tmp->addr = taddr;
					tmp->ip_count++;
					dnss_printf(DNSS_INFO,"add new ip:%s for old cache entry!\n",ipaddr_str(addr->addr4.s_addr));
				}
				
			}
			
			break;
		}
	
		up = &tmp->hnext;
	}

	if(!found) {
		if(cache_list_size == CACHESIZ)
		{
			tail_delete();
			cache_list_size--;
		}

		tmp = new_cache_malloc(name, addr, now, ttl, flags);
		if(tmp == NULL)
		{
			return -1;
		}
		
		if(cache_list)
			cache_list->prev = tmp;
		tmp->next = cache_list;
		tmp->prev = NULL;
		cache_list = tmp;
		if(!cache_tail)
			cache_tail =tmp;
		cache_list_size++;

		up = new_hash_bucket(name);
		tmp->hnext = *up;
  		*up = tmp;
		dnss_printf(DNSS_INFO,"add new cache,name:%s,ip:%s\n",name,ipaddr_str(addr->addr4.s_addr));
	} 
}

void cache_unlink(struct cache *tmp)
{

	if(tmp->prev)
		tmp->prev->next = tmp->next;
	else
		cache_list = tmp->next;

	if(tmp->next)
		tmp->next->prev = tmp->prev;
	else
		cache_tail = tmp->prev;

}


void cache_free(struct cache *tmp)
{
	struct list_addr *addr, *taddr;

	if(tmp->flag & F_BIGNAME)
		os_free(tmp->name.bname);

	addr = tmp->addr;

	while(addr)
	{
		taddr = addr;
		addr = addr->next;
		os_free(taddr);
	}
	os_free(tmp);
}

void tail_delete(void)
{
	struct cache *tmp = cache_tail;
	if(!cache_tail)
		return;
	cache_tail = cache_tail->prev;
	if(cache_tail)
		cache_tail->next = NULL;
	else
		cache_list = NULL;
	cache_free(tmp);
}
void cache_delete(char *name)
{
	struct cache **up, *tmp;

	for(up = new_hash_bucket(name), tmp = *up; tmp; tmp = tmp->hnext)
	{
		if(hostname_isequal(name, cache_get_tname(tmp)))
		{
			*up = tmp->hnext;
			cache_unlink(tmp);
			cache_free(tmp);
			return;
		}

		up = &tmp->hnext;
	}
}
void cache_printf(void)
{

	struct cache *tmp = cache_list;

	while(tmp)
	{
		dnss_printf(DNSS_INFO,"---------------------------------\n");
		dnss_printf(DNSS_INFO,"name = %s\n",cache_get_tname(tmp));
		dnss_printf(DNSS_INFO,"---------------------------------\n");
		struct list_addr *taddr = tmp->addr;
		while(taddr)
		{
			if(tmp->flag & F_IPV4)
			{
				dnss_printf(DNSS_INFO,"ip = %s\n",ipaddr_str(taddr->addr4.s_addr));
			}
			taddr = taddr->next;
		}
		dnss_printf(DNSS_INFO,"---------------------------------\n");
		tmp = tmp->next;
		
	}
	#if 0
	int i;
	struct cache *tmp;
	for(i = 0;i < cache_hash_size; i++)
	{
		for(tmp = cache_hash[i]; tmp; tmp = tmp->hnext)
		{
			dnss_printf(DNSS_DEBUG,"---------------------------------\n");
			dnss_printf(DNSS_DEBUG,"NAME:%s\n",cache_get_tname(tmp));
			dnss_printf(DNSS_DEBUG,"---------------------------------\n");
			struct list_addr *taddr = tmp->addr;
			while(taddr)
			{
				if(tmp->flag & F_IPV4)
				{
					dnss_printf(DNSS_DEBUG,"IP:%s\n",ipaddr_str(taddr->addr4.s_addr));
				}
				taddr = taddr->next;
			}
			dnss_printf(DNSS_DEBUG,"---------------------------------\n");
		}
	}
	#endif
}

int extract_name(struct dns_header *header, size_t plen, unsigned char **pp, 
		 char *name, int isExtract, int extrabytes)
{
  unsigned char *cp = (unsigned char *)name, *p = *pp, *p1 = NULL;
  unsigned int j, l, namelen = 0, hops = 0;
  int retvalue = 1;
  
  if (isExtract)
    *cp = 0;

  while (1)
    { 
      unsigned int label_type;
	  
      if (!CHECK_LEN(header, p, plen, 1))
		return 0;
	  
      if ((l = *p++) == 0) 
	/* end marker */
	{

	  /* check that there are the correct no of bytes after the name */
	  if (!CHECK_LEN(header, p1 ? p1 : p, plen, extrabytes))
	    return 0;
	 
	  if (isExtract)
	    {
	      if (cp != (unsigned char *)name)
		cp--;
	      *cp = 0; /* terminate: lose final period */
	    }
	  else if (*cp != 0)
	    retvalue = 2;
	  
	  if (p1) /* we jumped via compression */
	    *pp = p1;
	  else
	    *pp = p;
 
	  return retvalue;
	}

      label_type = l & 0xc0;
      
      if (label_type == 0xc0) /* pointer */
	{ 
	  if (!CHECK_LEN(header, p, plen, 1))
	    return 0;
	  
	  /* get offset */
	  l = (l&0x3f) << 8;
	  l |= *p++;
	  
	  if (!p1) /* first jump, save location to go back to */
	    p1 = p;
	      
	  hops++; /* break malicious infinite loops */
	  if (hops > 255)
	    return 0;
	  
	  p = l + (unsigned char *)header;
	}
      else if (label_type == 0x00)
	{ /* label_type = 0 -> label. */
	  namelen += l + 1; /* include period */
	  if (namelen >= MAXDNAME)
	    return 0;
	  
	  if (!CHECK_LEN(header, p, plen, l))
	    return 0;
	  
	  for(j=0; j<l; j++, p++)
	    if (isExtract)
	      {
		unsigned char c = *p;

		if (c != 0 && c != '.')
		  *cp++ = c;
		else
		  return 0;
		
	      }
	    else 
	      {
		unsigned char c1 = *cp, c2 = *p;
		
		if (c1 == 0)
		  retvalue = 2;
		else 
		  {
		    cp++;
		    if (c1 >= 'A' && c1 <= 'Z')
		      c1 += 'a' - 'A';
		    
		    if (c2 >= 'A' && c2 <= 'Z')
		      c2 += 'a' - 'A';
		     
		    if (c1 != c2)
		      retvalue =  2;
		  }
	      }
	    
	  if (isExtract)
	    *cp++ = '.';
	  else if (*cp != 0 && *cp++ != '.')
	    retvalue = 2;
	}
      else
	return 0; /* label types 0x40 and 0x80 not supported */
    }
}

unsigned char *skip_name(unsigned char *ansp, struct dns_header *header, size_t plen, int extrabytes)
{
  while(1)
    {
      unsigned int label_type;
      
      if (!CHECK_LEN(header, ansp, plen, 1))
	return NULL;
      
      label_type = (*ansp) & 0xc0;

      if (label_type == 0xc0)
	{
	  /* pointer for compression. */
	  ansp += 2;	
	  break;
	}
      else if (label_type == 0x80)
	return NULL; /* reserved */
      else if (label_type == 0x40)
	{
	  /* Extended label type */
	  unsigned int count;
	  
	  if (!CHECK_LEN(header, ansp, plen, 2))
	    return NULL;
	  
	  if (((*ansp++) & 0x3f) != 1)
	    return NULL; /* we only understand bitstrings */
	  
	  count = *(ansp++); /* Bits in bitstring */
	  
	  if (count == 0) /* count == 0 means 256 bits */
	    ansp += 32;
	  else
	    ansp += ((count-1)>>3)+1;
	}
      else
	{ /* label type == 0 Bottom six bits is length */
	  unsigned int len = (*ansp++) & 0x3f;
	  
	  if (!ADD_RDLEN(header, ansp, plen, len))
	    return NULL;

	  if (len == 0)
	    break; /* zero length label marks the end. */
	}
    }

  if (!CHECK_LEN(header, ansp, plen, extrabytes))
    return NULL;
  
  return ansp;
}

unsigned char *skip_questions(struct dns_header *header, size_t plen)
{
  int q;
  unsigned char *ansp = (unsigned char *)(header+1);

  for (q = ntohs(header->qdcount); q != 0; q--)
    {
      if (!(ansp = skip_name(ansp, header, plen, 4)))
	return NULL;
      ansp += 4; /* class and type */
    }
  
  return ansp;
}

unsigned char *skip_section(unsigned char *ansp, int count, struct dns_header *header, size_t plen)
{
  int i, rdlen;
  
  for (i = 0; i < count; i++)
    {
      if (!(ansp = skip_name(ansp, header, plen, 10)))
	return NULL; 
      ansp += 8; /* type, class, TTL */
      GETSHORT(rdlen, ansp);
      if (!ADD_RDLEN(header, ansp, plen, rdlen))
	return NULL;
    }

  return ansp;
}


