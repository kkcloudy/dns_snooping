/*******************************************************************************
			Copyright(c), 2009, Autelan Technology Co.,Ltd.
						All Rights Reserved

This software file is owned and distributed by Autelan Technology 
********************************************************************************

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND 
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED 
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE 
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR 
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES 
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; 
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON 
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT 
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS 
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
********************************************************************************
*	RCSfile   :  eag_iptables.c
*
*	Author   :  wangke
*
*	Revision :  1.00
*
*	Date      :  2010-1-5
********************************************************************************/

/*********************************************************
*	head files											 *
**********************************************************/
#include <getopt.h>
#include <sys/errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <time.h>
#include <iptables.h>
#include <arpa/inet.h>
#include <linux/netfilter/nf_nat.h>
#include <pthread.h>
#include <syslog.h>
#include <netdb.h>
#include <linux/netfilter/xt_iprange.h> 	/* -m iprange */
#include <linux/netfilter/xt_multiport.h>	/* -m multiport */
#include <linux/netfilter/xt_string.h>	/* -m string */
#include <linux/netfilter/xt_comment.h>	/* -m comment */
#include <linux/netfilter/x_tables.h>	/* -m comment */
#include <linux/netfilter/xt_physdev.h>  /*-m physdev*/
#include "common.h"
#include "dns_errcode.h"
#include "debug.h"
#include "dns_iptables.h"
#include "nmp_process.h"
#include "list.h"

#define USE_THREAD_LOCK		0
#define CP_DNSS 		"CP_DNSS"
#define DNSS_DNAT 		"DNSS_DNAT"
#define TARGET_NAME      "ACCEPT"
extern char filter_name[MAX_IPTABLES_LIST][FILTER_NAME_LENTH];
extern char nat_filter_name[MAX_IPTABLES_LIST][FILTER_NAME_LENTH];


struct dns_ipt_matches {
	struct dl_list node;
	struct ipt_entry_match *match;
};

struct dns_ipt_entries {
	struct dl_list node;
	struct ipt_entry *entry;
};



/*********************************************************
*	global variable define									  *
**********************************************************/
#if USE_THREAD_LOCK
static pthread_mutex_t dns_iptables_glock;
#endif

nmp_mutex_t dns_iptables_lock = {-1, ""};



static int 
check_is_chain(const char * table_name,const char * chain_name)
{
	int ret = DNS_RETURN_OK;
	struct iptc_handle *handle = NULL;
	if (NULL == table_name || NULL == chain_name)
	{
		dnss_printf(DNSS_ERROR, "function check_is_chain  error,input error\n");
		return DNS_ERR_INPUT_PARAM_ERR;
	}
	nmp_mutex_lock(&dns_iptables_lock);
	handle = iptc_init(table_name);
	nmp_mutex_unlock(&dns_iptables_lock);
	if (NULL == handle)
	{
		dnss_printf(DNSS_INFO, "function check_is_chain  error,can't init iptc handle,"\
			        "table name:%s\n",table_name);
		ret = DNS_ERR_UNKNOWN;
	}
	else if (!iptc_is_chain(chain_name, handle))/*check chain exist*/
	{
		dnss_printf(DNSS_DEBUG, "chain is not exist in the table,chain name:%s,"\
			        "table name:%s\n",chain_name,table_name);
		ret = IP_CHAIN_CREATE;
	}
	
	if (NULL != handle)
	{
		iptc_free(handle);
		handle = NULL;
	}
	return ret;
}

/*******************************************************************
 *	get_index_of_entry
 * 
 *	DESCRIPTION:
 *		Serch is the entry exist
 *
 *	INPUT:
 *		table_name 	- table name
 *		chain_name 	- chain name
 *		ip_addr		- ip address
 *		type			- the input ip is source or destination
 *	
 *	OUTPUT:
 *		num_of_entry - the num of the entry
 *
 *	RETURN:
 *		EAG_ERR_UNKNOWN		- error
 *		EAG_RETURN_CODE_NOT_FOUND - not exist
 *		EAG_RETURN_OK 		- success ,entry is exist
 *
 *********************************************************************/
static int 
get_index_of_entry(	const char * table_name,const char * chain_name,
							const unsigned int ip_addr,const int type )
{	
	const struct ipt_entry *p_entry = NULL;
	//const struct ipt_counters *my_counter = NULL;
	struct iptc_handle *handle = NULL;
	unsigned int index = 1;
	char ip_str[32] = "";
	
	ip2str( ip_addr, ip_str, sizeof(ip_str) );
	
	/* check input */
	if (DNS_IPTABLES_SOURCE != type && DNS_IPTABLES_DESTINATION != type)
	{
		dnss_printf(DNSS_ERROR,"input error,input:%d\n",type);
		return -1;
	}
	
	if (0 == ip_addr>>24)
	{
		dnss_printf(DNSS_ERROR,"ip range error! ip_addr == %s\n",ip_str);	
		return -1;
	}
	
	if (NULL == table_name || NULL == chain_name)
	{
		dnss_printf(DNSS_ERROR,"input counter_info is NULL\n");
		return -1;
	}
	
	/* iptc handle */
	nmp_mutex_lock(&dns_iptables_lock);
	handle = iptc_init(table_name);
	nmp_mutex_unlock(&dns_iptables_lock);
	if (NULL == handle)
	{
		dnss_printf(DNSS_ERROR,"can't init iptc handle,table name:%s\n",table_name);
		return -1;
	}

	/* get rules */
	if (DNS_IPTABLES_SOURCE == type)
	{
		for	(p_entry = iptc_first_rule((const char *)chain_name, handle);
			p_entry;
			p_entry = iptc_next_rule(p_entry, handle))
		{
			//my_counter = iptc_read_counter(chain_name,index, handle);
			//eag_log_dbg("chain_name=%s,ip_addr=%#X,p_entry->ip.src.s_addr=%#X",chain_name,ip_addr,p_entry->ip.src.s_addr);
			if (ip_addr == p_entry->ip.src.s_addr)
			{				
				//return index;
				goto find;
			}
			index++;
		}
	}
	else if (DNS_IPTABLES_DESTINATION == type)
	{
		for	(p_entry = iptc_first_rule(chain_name, handle);
			p_entry;
			p_entry = iptc_next_rule(p_entry, handle))
		{
			//my_counter = iptc_read_counter(chain_name,index, handle);
			//eag_log_dbg("ip_addr=%#X,p_entry->ip.dst.s_addr=%#X",ip_addr,p_entry->ip.dst.s_addr);			
			if (ip_addr == p_entry->ip.dst.s_addr)
			{
				//return index;
				goto find;
			}
			index++;
		}
	}
	
	iptc_free(handle);
	handle = NULL;

	return 0;

find:
	iptc_free(handle);
	handle = NULL;

	return index;
}

/*******************************************************************
 *	add_and_del_entry
 * 
 *	DESCRIPTION:
 *		Add or delete the enty
 *
 *	INPUT:
 *		table_name 	- table name
 *		chain_name 	- chain name
 *		dest_ip		- destination ip address
 *		source_ip		- source ip address
 *		target_name	- target name
 *		type			- the input ip is source or destination
 *	
 *	OUTPUT:
 *		NULL
 *
 *	RETURN:
 *		EAG_ERR_UNKNOWN		- error
 *		EAG_RETURN_OK 		- success
 *
 *********************************************************************/
static int 
add_and_del_entry(const char *table_name,const char *chain_name,
							const int source_ip,const int dest_ip,
							const char *target_name,const int type)
{
	struct ipt_entry *p_entry = NULL;
	struct ipt_entry_target *p_target  = NULL;
//	struct ipt_entry_match *p_match = NULL;
//	struct ipt_tcp *ptcp = NULL;
	struct iptc_handle *handle = NULL;
	size_t entry_size = 0;
	size_t target_size = 0;
	size_t match_size = 0;
	size_t all_size = 0;
//	int i = 0;
	int return_ret = DNS_RETURN_OK;
	char dest_ip_str[32] = "";
	char source_ip_str[32] = "";

#if USE_THREAD_LOCK	
	dnss_printf(DNSS_DEBUG,"iptables add_and_del_entry lock\n");
	pthread_mutex_lock( &dns_iptables_glock );
#endif
/*use iptables lock*/

	dnss_printf(DNSS_DEBUG,"iptables add_and_del_entry lock \n");
	nmp_mutex_lock(&dns_iptables_lock);
	
	ip2str( dest_ip, dest_ip_str, sizeof(dest_ip_str) );
	ip2str( source_ip, source_ip_str, sizeof(source_ip_str) );
	
	/* check input */
	if (DNS_IPTABLES_ADD != type && DNS_IPTABLES_DELTE != type)
	{
		dnss_printf(DNSS_ERROR,"input error,input:%d\n",type);
		goto return_error;
	}
	if ((0 == dest_ip>>24) && (0 == source_ip>>24))
	{
		dnss_printf(DNSS_ERROR,"ip range error! dest_ip == %s,source_ip == %s\n",dest_ip_str,source_ip_str);	
		goto return_error;
	}
	if (NULL == table_name || NULL == chain_name || NULL == target_name)
	{
		dnss_printf(DNSS_ERROR,"input counter_info is NULL\n");
		goto return_error;
	}
	
	#if 0//if need NAT,use this
	int is_nat;
	if(!strcmp(table_name,"nat"))
	{
		is_nat = 1;
	}else if(!strcmp(table_name,"filter"))
	{
		is_nat = 0;
	}else
	{
		return 0;
	}
	#endif
	
	handle = iptc_init(table_name);
	if ( NULL == handle)
	{
		dnss_printf(DNSS_DEBUG,"iptables can't init iptc handle,table name:%s\n",table_name);
		goto return_error;
	}

	entry_size = XT_ALIGN(sizeof(struct ipt_entry));

	match_size = 0;
	#if 0//if match port ,use this
	match_size = IPT_ALIGN(sizeof(struct ipt_entry_match)) + IPT_ALIGN(sizeof(struct ipt_tcp));
	#endif
	#if 0//if NAT,use this
	target_size = IPT_ALIGN(sizeof(struct ipt_entry_target));
	if(is_nat)
	{
		target_size += IPT_ALIGN(sizeof(struct ip_nat_multi_range));//nat		
	}else
	{
		target_size += IPT_ALIGN(sizeof(int));
	}
	#endif
	target_size = XT_ALIGN(sizeof(struct ipt_entry_target))+XT_ALIGN(sizeof(int));
	all_size = target_size + match_size + entry_size;

	p_entry = malloc(all_size);
	memset(p_entry, 0, all_size);

	/* Set tha Entry part of the entry */
	/* Set source and destination IP address */
	p_entry->ip.src.s_addr = htonl(source_ip);	
	p_entry->ip.dst.s_addr = htonl(dest_ip);	
	if (0 == source_ip)
	{
		p_entry->ip.smsk.s_addr = 0x0;
	}
	else
	{
		p_entry->ip.smsk.s_addr = htonl(-1);
		//e->ip.smsk.s_addr = 0xffffffff;
	}
	if(0 == dest_ip)
	{
		p_entry->ip.dmsk.s_addr = 0x0;
	}
	else
	{
		p_entry->ip.dmsk.s_addr = htonl(-1);
		//e->ip.smsk.s_addr = 0xffffffff;
	}	
	/* Set the interface */
	#if 0
	if(strcmp(interface_name,"0"))
	{
		strcpy (p_entry->ip.iniface,interface_name);
		//for(i=strlen(interface_name);i>-1;i--)
		for(i=0;i<strlen(interface_name)+1;i++)
		{
			p_entry->ip.iniface_mask[i] = 0xff;
		}
	}
	#endif	
	/* Set the portol num(tcp 6,udp 17,icmp 1,IPv6 41,ALL 0) */
	#if 0
	if(!strcmp(portol_name,"tcp"))
	{
		p_entry->ip.proto = 6;
	}else if(!strcmp(portol_name,"udp"))
	{
		p_entry->ip.proto = 17;
	}else if(!strcmp(portol_name,"icmp"))
	{
		p_entry->ip.proto = 1;
	}else if(!strcmp(portol_name,"ipv6"))
	{
		p_entry->ip.proto = 41;
	}else
	{
		p_entry->ip.proto = 0;
	}
	#endif
	/* Set the proto (it's ALL here) */
	p_entry->ip.proto = 0;
	/* Set the size */
	p_entry->target_offset = entry_size + match_size;
	p_entry->next_offset = all_size;

	/* Set the ipt_entry_match part of the entry */
	#if 0//if match port,use it
	//Get address
	p_match = (struct ipt_entry_match*)p_entry->elems;
	p_match->u.user.match_size = match_size;
	//Set the portol name
	//strcpy(p_match->u.user.name,portol_name);
	//Set the Match Data of Match part----------------
	//Get address
	ptcp = (struct ipt_tcp*)p_match->data;
	//Set the port 	(All the port is match)
	ptcp->spts[0]=0;ptcp->spts[1]=0xffff;
	ptcp->dpts[0]=0;ptcp->dpts[1]=0xffff;
	#endif

	/* Set the ipt_entry_target part of the entry */
	/* Get address */
	p_target = (struct ipt_entry_target*)(p_entry->elems+match_size);
	p_target->u.user.target_size = target_size;
	/* Set the target */
	strcpy(p_target->u.user.name,target_name);
	//strcpy(pt->u.user.name,"SNAT");
	#if 0//if NAT
	struct ip_nat_multi_range *p_nat;
	p_nat = (struct ip_nat_multi_range *) p_target->data;
	p_nat->rangesize = 1;// 该nat不做随机的选择 ,>1为多NAT	
	p_nat->range[0].flags = IP_NAT_RANGE_PROTO_SPECIFIED |
		IP_NAT_RANGE_MAP_IPS;	
	p_nat->range[0].min.tcp.port = p_nat->range[0].max.tcp.port = 0;
	p_nat->range[0].min_ip = p_nat->range[0].max_ip = inet_addr("4.4.4.4");
	#endif
	
	/* add or del */
	if (DNS_IPTABLES_ADD == type)
	{
		//iptc_append_entry(chain_name,e,&h);//---append is insert in to the last
		if (!iptc_insert_entry(chain_name,p_entry,0,handle))
		{
			dnss_printf(DNSS_ERROR,"add iptables error: %d,%s. table==%s,chain==%s,s_ip==%s,"\
						"d_ip==%s,target==%s,handle=%p\n",
						errno, iptc_strerror(errno), table_name, chain_name,
						source_ip_str, dest_ip_str, target_name, handle);
			goto return_error;
		}
	}
	else if (DNS_IPTABLES_DELTE == type)
	{
		if (!iptc_delete_entry(chain_name,p_entry,NULL,handle))
		{
			dnss_printf(DNSS_ERROR,"del iptables error: %d,%s table==%s,chain==%s,s_ip==%s,"\
						"d_ip==%s,target==%s,handle=%p\n",
						errno, iptc_strerror(errno), table_name, chain_name,
						source_ip_str, dest_ip_str, target_name, handle);
			goto return_error;
		}
	}
	
	if (!iptc_commit(handle))
	{
		dnss_printf(DNSS_ERROR,"commit iptables error: %d,%s.\n table==%s,chain==%s,s_ip==%s,d_ip==%s,target==%s,handle=%p\n",
						errno, iptc_strerror(errno), table_name, chain_name,
						source_ip_str, dest_ip_str, target_name, handle);
		goto return_error;
	}
//return_success:
	return_ret = DNS_RETURN_OK;
	goto return_line;
	
return_error:
	return_ret = DNS_ERR_UNKNOWN;
	goto return_line;

return_line:
	
	if (NULL != p_entry)
	{
		free(p_entry);
		p_entry = NULL;
	}		
	
	if (NULL != handle)
	{
		iptc_free(handle);
		handle = NULL;
	}
	
	//log_dbg("add_and_del_entry will unlock");
#if USE_THREAD_LOCK	
	pthread_mutex_unlock( &dns_iptables_glock );
	dnss_printf(DNSS_DEBUG,"iptables add_and_del_entry unlock\n");
#endif

/*use iptable unlock*/
	nmp_mutex_unlock(&dns_iptables_lock);
	dnss_printf(DNSS_DEBUG,"iptables add_and_del_entry unlock\n");
	
	return return_ret;
}

/*******************************************************************
 *	connect_up
 * 
 *	DESCRIPTION:
 *		Add the ip to the iptables
 *
 *	INPUT:
 *		user_id 		- user captive portal id
 *		user_interface	- interface name
 *		user_ip		- user ip
 *
 *	OUTPUT:
 *		NULL
 *
 *	RETURN:
 *		EAG_ERR_UNKNOWN		- error
 *		EAG_RETURN_OK 		- success
 *
 *********************************************************************/

int 
connect_up(const unsigned int user_ip,int domain_id)
{
	int entry_num = 0;
//	int return_ret = EAG_ERR_UNKNOWN;
	char ip_str[32] = "";

	//char *cpid_prefix = NULL;

		
	//cpid_prefix = (HANSI_LOCAL==hansitype)?"L":"R";
	ip2str(user_ip, ip_str, sizeof(ip_str));
	
	/* search if the chain is exist */
	if (DNS_RETURN_OK != check_is_chain("filter",filter_name[domain_id])
		|| DNS_RETURN_OK != check_is_chain("nat",nat_filter_name[domain_id]))
	{
		dnss_printf(DNSS_INFO, "connect_up error,one or more chain is not exist,chain:%s,%s\n",
						filter_name[domain_id],nat_filter_name[domain_id]);
		return DNS_ERR_UNKNOWN;
	}
#if 0
	/* serch if the entry is exist */
	entry_num = get_index_of_entry("filter",filter_name[domain_id],htonl(user_ip),DNS_IPTABLES_SOURCE);
	if ( entry_num < 0 ){
		dnss_printf(DNSS_ERROR,"connect_up  error. input param might error!");
		return DNS_ERR_UNKNOWN;
	}else if( entry_num > 0 )
	{
		dnss_printf(DNSS_INFO,"connect_up error,entry is exist in the chain of table "\
					"\"filter\":user_ip==%s,chain_name==%s",ip_str,filter_name[domain_id]);
		return DNS_ERR_UNKNOWN;
	}
#endif
	/* add the entry */
	if	(DNS_RETURN_OK != add_and_del_entry("filter",filter_name[domain_id],
							user_ip,0,TARGET_NAME,DNS_IPTABLES_ADD)
		|| DNS_RETURN_OK !=  add_and_del_entry("filter",filter_name[domain_id],0,
							user_ip,TARGET_NAME,DNS_IPTABLES_ADD)
		|| DNS_RETURN_OK !=  add_and_del_entry("nat",nat_filter_name[domain_id],
							user_ip,0,TARGET_NAME,DNS_IPTABLES_ADD)
		|| 	DNS_RETURN_OK !=  add_and_del_entry("nat",nat_filter_name[domain_id],0,
							 user_ip,TARGET_NAME,DNS_IPTABLES_ADD))
	{
		dnss_printf(DNSS_ERROR,"connect_up error, add entry error\n");
		return DNS_ERR_UNKNOWN;
	}

	return DNS_RETURN_OK;
}

/*******************************************************************
 *	connect_down
 * 
 *	DESCRIPTION:
 *		Delete the ip from the iptables
 *
 *	INPUT:
 *		user_id 		- user captive portal id
 *		user_interface	- interface name
 *		user_ip		- user ip
 *
 *	OUTPUT:
 *		NULL
 *
 *	RETURN:
 *		EAG_ERR_UNKNOWN		- error
 *		EAG_RETURN_OK 		- success
 *
 *********************************************************************/
int 
connect_down(const unsigned int user_ip,int domain_id)
{
//	int entry_num = 0;
//	int return_ret = EAG_ERR_UNKNOWN;
	char chain_name[256];
	char chain_name_nat[256];	
	char target_name[256];
	char target_name_nat[256];
	char ip_str[32] = "";
	
	
	ip2str(user_ip, ip_str, sizeof(ip_str));
	
	/* check input */
	if (domain_id < 0)
	{
		dnss_printf(DNSS_ERROR,"connect_down error. no user_interface input\n");		
		return DNS_ERR_INPUT_PARAM_ERR;
	}
	if (0 == user_ip>>24)
	{
		dnss_printf(DNSS_ERROR,"connect_down error. ip range error! ip_addr == %s\n",ip_str);	
		return DNS_ERR_INPUT_PARAM_ERR;
	}
	
	memset(chain_name,0,sizeof(chain_name));
	memset(chain_name_nat,0,sizeof(chain_name_nat));
	memset(target_name,0,sizeof(target_name));
	memset(target_name_nat,0,sizeof(target_name_nat));
	
	snprintf(chain_name,sizeof(chain_name),"CP_domain_%d",domain_id);
	snprintf(chain_name_nat,sizeof(chain_name_nat),"DNSS_DNAT_%d",domain_id);
	snprintf(target_name,sizeof(target_name),"ACCEPT");
	snprintf(target_name_nat,sizeof(target_name_nat),"ACCEPT");
	
	/* search if the chain is exist */
	if (DNS_RETURN_OK != check_is_chain("filter",chain_name) 
		|| DNS_RETURN_OK != check_is_chain("nat",chain_name_nat))
	{
		dnss_printf(DNSS_INFO,"connect_down error,one or more chain is not exist,chain:%s,%s\n",chain_name,chain_name_nat);
		return DNS_ERR_UNKNOWN;
	}
	
	/* del the entry */
	if	(DNS_RETURN_OK != add_and_del_entry("filter",chain_name,
								user_ip,0,target_name,DNS_IPTABLES_DELTE)
		|| DNS_RETURN_OK !=  add_and_del_entry("filter",chain_name,0,
								user_ip,target_name,DNS_IPTABLES_DELTE)
		|| DNS_RETURN_OK !=  add_and_del_entry("nat",chain_name_nat,
								user_ip,0,target_name_nat,DNS_IPTABLES_DELTE) )
	{
		dnss_printf(DNSS_ERROR,"connect_down error,delete entry error\n");
		return DNS_ERR_UNKNOWN;
	}

	return DNS_RETURN_OK;
}

void parse_iniface(const char *str, struct ipt_entry *fw)
{
	int i = 0;
	strcpy (fw->ip.iniface, str);
	for(i = 0; i < strlen(str) + 1; i++) {
		fw->ip.iniface_mask[i] = 0xff;
	}
}

void parse_outiface(const char *str, struct ipt_entry *fw)
{
	int i = 0;
	strcpy (fw->ip.outiface, str);
	for(i = 0; i < strlen(str) + 1; i++) {
		fw->ip.outiface_mask[i] = 0xff;
	}
}

static int dns_match_physdev(const char *setname, const int flag,const char *intf,
							struct xt_entry_match *match, size_t size)
{
	match = (struct xt_entry_match *)match;
	match->u.match_size = size;
	strcpy(match->u.user.name, "physdev");
	
	struct xt_physdev_info *info = (struct xt_physdev_info *)match->data;
	if(flag == DNS_INTERFACE_IN)
	{
                strcpy(info->physindev,intf );
                 memset(info->in_mask, 0xFF, IFNAMSIZ);
                info->bitmask = XT_PHYSDEV_OP_IN;
	}
	else if(flag == DNS_INTERFACE_OUT)
	{
	       strcpy(info->physoutdev,intf );
                 memset(info->out_mask, 0xFF, IFNAMSIZ);
                info->bitmask = XT_PHYSDEV_OP_OUT;

	}

	//struct ipt_set_info_match *myinfo = (struct ipt_set_info_match *)match->data;
	//struct ipt_set_info *info = &myinfo->match_set;

	//info->index = eag_get_set_byname(setname);
	//parse_bindings(setflag, info);

	return 0;
	
}

struct ipt_entry *dns_iptable_entry_new(const struct ipt_entry *fw,
		struct dl_list *ipt_match_node,
		struct ipt_entry_target *target)
{
	struct ipt_entry *p_entry;
	struct dns_ipt_matches *matchp;
	size_t size = 0;
	int i = 0;
	
	size = XT_ALIGN(sizeof(struct ipt_entry));
	dl_list_for_each(matchp, ipt_match_node,struct dns_ipt_matches, node) {
		size += matchp->match->u.match_size;
	}

	p_entry = malloc(size + target->u.target_size);
	if (NULL == p_entry) {
		dnss_printf(DNSS_ERROR,"malloc error:p_entry = NULL\n");
		return p_entry;
	}

	*p_entry = *fw;	
	p_entry->target_offset = size;
	p_entry->next_offset = size + target->u.target_size;
	p_entry->ip.src.s_addr = 0x0;	
	p_entry->ip.dst.s_addr = 0x0;	
	p_entry->ip.smsk.s_addr = 0x0;
	p_entry->ip.dmsk.s_addr = 0x0;
	
	size = 0;

	if (0 == dns_list_empty_careful(ipt_match_node)) {
		dl_list_for_each(matchp, ipt_match_node,struct dns_ipt_matches,node) {
			memcpy(p_entry->elems + size, matchp->match,
				matchp->match->u.match_size);
			size += matchp->match->u.match_size;
			i++;
		}
	}
	//eag_log_info( "match count:%d", i);		
	memcpy(p_entry->elems + size, target, target->u.target_size);

	return p_entry;
	
}	
		
struct ipt_entry *dns_add_del_intf_entry(struct dns_intf_entry_info *info)
{
	struct ipt_entry fw, *p_entry = NULL;
	struct dl_list ipt_match_node = {0};
	struct dns_ipt_matches *matchp = NULL;
	struct dns_ipt_matches *tmp = NULL;
	struct ipt_entry_target *target = NULL;
	size_t size;

	memset(&fw, 0, sizeof(fw));
	dl_list_init(&ipt_match_node);
		
/* match */
	fw.ip.proto = 0;
	if (info->intf_flag == DNS_INTERFACE_IN && info->intf != NULL) {
		parse_iniface(info->intf, &fw);
		dnss_printf(DNSS_DEBUG,"match:iniface\n");
	}
	if (info->intf_flag == DNS_INTERFACE_OUT && info->intf != NULL) {
		parse_outiface(info->intf, &fw);
		dnss_printf(DNSS_DEBUG,"match:outiface\n");
	}

	
	/*if (info->setflag != NULL && !strcmp(info->setflag, "tcp")) {
		int port =0;
		matchp = eag_calloc(1, sizeof(struct eag_ipt_matches));
		if (NULL == matchp) {
			eag_log_err("eag_add_del_intf_entry calloc set error");
			goto return_error;
		}
		size = XT_ALIGN(sizeof(struct ipt_entry_match))
			+ XT_ALIGN(sizeof(struct ipt_tcp));
		matchp->match = eag_calloc(1, size);
		if (NULL == matchp->match) {
			eag_log_err("eag_add_del_intf_entry calloc set error");
			eag_free(matchp);
			goto return_error;
		}
		eag_log_info( "match:tcp, name:%s, intf:%s, size:%u", 
					info->setflag, info->intf, size);
		for( i =0; i < intf_num; i ++)
		{
                            if(!strcmp(info->intf,global_intf[i]))
				break;
			else 
				i++;
		}
		port = 3990+i;
	         	eag_match_tcp(port,matchp->match, size);

		eag_list_add(&(matchp->node), &ipt_match_node);
	}*/
	
	if (info->setname != NULL && info->intf!= NULL &&\
		(info->intf_flag == DNS_INTERFACE_IN ||info->intf_flag == DNS_INTERFACE_OUT)  && strcmp(info->setname, "")) {
		matchp = calloc(1, sizeof(struct dns_ipt_matches));
		if (NULL == matchp) {
			dnss_printf(DNSS_ERROR,"eag_add_del_intf_entry calloc set error\n");
			goto return_error;
		}
		size = XT_ALIGN(sizeof(struct ipt_entry_match))
			+ XT_ALIGN(sizeof(struct xt_physdev_info));
		matchp->match = calloc(1, size);
		if (NULL == matchp->match) {
			dnss_printf(DNSS_ERROR,"eag_add_del_intf_entry calloc set error\n");
			free(matchp);
			goto return_error;
		}
		/*eag_log_info( "match:physdev, name:%s, intf:%s, size:%u", 
					info->setname, info->intf, size);*/
		dns_match_physdev(info->setname, info->intf_flag,info->intf, matchp->match, size);
		dl_list_add(&(matchp->node), &ipt_match_node);
	}


/* target */
	size= XT_ALIGN(sizeof(struct ipt_entry_target))+XT_ALIGN(sizeof(int));
	target = calloc(1, size);
	if (NULL == target) {
		dnss_printf(DNSS_ERROR,"calloc error:target = NULL\n");
		goto return_error;
	}

	target->u.target_size = size;
	strcpy(target->u.user.name, info->target);
	/*eag_log_info( "target_name:%s, target_size:%u", 
		target->u.user.name, target->u.target_size);*/

/* entry */
	p_entry = dns_iptable_entry_new(&fw, &ipt_match_node, target);
	goto return_line;
	
return_error:
	p_entry = NULL;
return_line:
	dl_list_for_each_safe(matchp, tmp, &ipt_match_node,struct dns_ipt_matches,node)
	{
		if (NULL != matchp->match) {
			free(matchp->match);
			matchp->match = NULL;	
		}		
		free(matchp);
		matchp = NULL;
	}

	if (NULL != target) {
		free(target);
		target = NULL;
	}
	return p_entry;
}

int dns_iptable_add_interface_filter_commit( char *intf, char *setname,int domain_id)
{	

	char cap_auth_intf_chain[DNS_IPTABLES_MAXNAMESIZE] = {0};	//CP_FILTER_AUTH_IF
	snprintf(cap_auth_intf_chain, DNS_IPTABLES_MAXNAMELEN, "CP_domain_%d", domain_id);

	struct iptc_handle *handle = NULL;
	struct ipt_entry *entry = NULL;
	struct dns_intf_entry_info intf_info = {0};
	int ret = 0;

#if USE_THREAD_LOCK	
	dnss_printf(DNSS_DEBUG,"dns_iptable_glock lock\n");
	pthread_mutex_lock( &dns_iptables_glock );
#endif
	/*use iptables lock*/
	dnss_printf(DNSS_DEBUG,"iptable_lock lock \n");
	nmp_mutex_lock(&dns_iptables_lock);
	
	handle = iptc_init("filter");
	if (!handle) {
		dnss_printf(DNSS_ERROR,"dns_iptable_add_interface_filter_commit iptc_init error:%s\n", iptc_strerror(errno));
		goto return_line;
	}
	if(IP_CHAIN_CREATE == check_is_chain("filter",cap_auth_intf_chain))
	{
	/* iptables -N $CP_FILTER_AUTH_IF */
		ret = iptc_create_chain(cap_auth_intf_chain, handle);
		if (!ret) {
			dnss_printf(DNSS_ERROR,"dns_iptable_add_interface_filter_commit iptc_create_chain %s error:%s\n", 
								cap_auth_intf_chain, iptc_strerror(errno));
			goto return_line;
		}
	}

	memset(&intf_info, 0, sizeof(struct dns_intf_entry_info));
	intf_info.chain = CP_DNSS;
	intf_info.intf = intf;
	intf_info.intf_flag = DNS_INTERFACE_IN;
	intf_info.target = cap_auth_intf_chain;
	entry = dns_add_del_intf_entry(&intf_info);
	ret = iptc_insert_entry(intf_info.chain, entry, 0, handle);
	if (!ret) {
		dnss_printf(DNSS_ERROR,"eag_iptable_add_interface_filter_commit iptc_insert_entry %s error:%s\n",
								intf_info.chain, iptc_strerror(errno));
		goto return_line;
	}
	free(entry);
	entry = NULL;

	ret = iptc_commit(handle);
	if (!ret) {
		dnss_printf(DNSS_ERROR,"eag_iptable_add_interface_filter_commit iptc_commit:%s\n", iptc_strerror(errno));
	}
	

return_line:
	if (NULL != entry) {
		free(entry);
		entry = NULL;
	}
	if (NULL != handle) {
		iptc_free(handle);
		handle = NULL;
	}

#if USE_THREAD_LOCK	
	pthread_mutex_unlock( &dns_iptables_glock );
	dnss_printf(DNSS_DEBUG,"dns_iptable_glock unlock\n");
#endif
	/*use iptable unlock*/
	nmp_mutex_unlock(&dns_iptables_lock);
	dnss_printf(DNSS_DEBUG,"iptable_lock unlock\n");

	return ret;
}

int
dns_iptable_add_interface_nat_commit(char *intf, char *setname,int domain_id)
{
	char cap_nat_default_chain[DNS_IPTABLES_MAXNAMESIZE] = {0};		//CP_NAT_DEFAULT
	snprintf(cap_nat_default_chain, DNS_IPTABLES_MAXNAMELEN, "DNSS_DNAT_%d",domain_id);

	struct iptc_handle *handle = NULL;
	struct ipt_entry *entry = NULL;
	struct dns_intf_entry_info intf_info = {0};
	int ret = 0;

#if USE_THREAD_LOCK	
	dnss_printf(DNSS_DEBUG,"dns_iptable_glock lock\n");
	pthread_mutex_lock( &dns_iptables_glock );
#endif
	/*use iptables lock*/
	dnss_printf(DNSS_DEBUG,"iptable_lock lock \n");
	nmp_mutex_lock(&dns_iptables_lock);
	
	handle = iptc_init("nat");
	if (!handle) {
		dnss_printf(DNSS_ERROR,"dns_iptable_add_interface_nat_commit iptc_init error:%s\n", iptc_strerror(errno));
		goto return_line;
	}

	
	if(IP_CHAIN_CREATE == check_is_chain("nat",cap_nat_default_chain))
	{
		/*iptables -t nat -N $CP_NAT_AUTH_IF*/
		ret = iptc_create_chain(cap_nat_default_chain, handle);
		if (!ret) {
			dnss_printf(DNSS_ERROR,"dns_iptable_add_interface_nat_commit iptc_create_chain %s error:%s\n", 
								cap_nat_default_chain, iptc_strerror(errno));
			goto return_line;
		}
	}

/* iptables -t nat -I CP_DNAT -m physdev --physdev-in ${CP_IF} -j $CP_NAT_DEFAULT_${CP_IF}*/
	memset(&intf_info, 0, sizeof(struct dns_intf_entry_info));
	intf_info.chain = DNSS_DNAT;
	intf_info.intf = intf;
	intf_info.intf_flag = DNS_INTERFACE_IN;
	intf_info.target = cap_nat_default_chain;
	entry = dns_add_del_intf_entry(&intf_info);
	ret = iptc_insert_entry(intf_info.chain, entry, 0, handle);
	if (!ret) {
		dnss_printf(DNSS_ERROR,"eag_iptable_add_interface_nat_commit iptc_insert_entry %s error:%s\n",
							intf_info.chain, iptc_strerror(errno));
		goto return_line;
	}
	
	free(entry);
	entry = NULL;

	ret = iptc_commit(handle);
	if (!ret) {
		dnss_printf(DNSS_ERROR,"dns_iptable_add_interface_nat_commit iptc_commit:%s\n", iptc_strerror(errno));
	}
	
return_line:
	if (NULL != entry) {
		free(entry);
		entry = NULL;
	}
	if (NULL != handle) {
		iptc_free(handle);
		handle = NULL;
	}

#if USE_THREAD_LOCK	
	pthread_mutex_unlock( &dns_iptables_glock );
	dnss_printf(DNSS_DEBUG,"dns_iptable_glock unlock\n");
#endif
	/*use iptable unlock*/
	nmp_mutex_unlock(&dns_iptables_lock);
	dnss_printf(DNSS_DEBUG,"iptable_lock unlock\n");

	return ret;
}

int dns_iptable_add_interface(char *intf,int domain_id)
{
	int ret = 0;
	char cap_iphash_set[DNS_IPTABLES_MAXNAMESIZE] = {0};

	//snprintf(cap_iphash_set, EAG_IPTABLES_MAXNAMELEN, "CP_AUTHORIZED_SET");

	ret = dns_iptable_add_interface_filter_commit(intf, cap_iphash_set,domain_id);
	if (!ret) {
		dnss_printf(DNSS_ERROR,"dns_iptable_add_interface_filter_commit error:ret=%d\n", ret);
		return DNS_ERR_UNKNOWN;
	}
	ret = dns_iptable_add_interface_nat_commit(intf, cap_iphash_set,domain_id);
	if (!ret) {
		dnss_printf(DNSS_ERROR,"dns_iptable_add_interface_nat_commit error:ret=%d\n", ret);
		return DNS_ERR_UNKNOWN;
	}
	
	return DNS_RETURN_OK;
}

static unsigned char *
iptable_mask(size_t all_size)
{

	unsigned char *mask;
	mask = calloc(1, all_size);
	if (NULL == mask) {
		dnss_printf(DNSS_ERROR,"calloc error:mask = NULL\n");
		return NULL;
	}
	memset(mask, 0xFF, all_size);
	return mask;
}


int dns_iptable_del_interface_filter_commit( char * intf,int domain_id,int type)
{
	char cap_auth_intf_chain[DNS_IPTABLES_MAXNAMESIZE] = {0};	//CP_FILTER_AUTH_IF
	snprintf(cap_auth_intf_chain, DNS_IPTABLES_MAXNAMELEN, "CP_domain_%d", domain_id);
	dnss_printf(DNSS_INFO,"dns_iptable_del_interface_filter_commit  %s domian_id %d type %d intf %s\n",cap_auth_intf_chain,domain_id,type,intf);

	struct iptc_handle *handle = NULL;
	struct ipt_entry *entry = NULL;
	struct dns_intf_entry_info intf_info = {0};
	unsigned char *mask = NULL;
	int ret = 0;

#if USE_THREAD_LOCK	
	dnss_printf(DNSS_DEBUG,"dns_iptable_glock lock\n");
	pthread_mutex_lock( &dns_iptables_glock );
#endif
	/*use iptables lock*/
	dnss_printf(DNSS_DEBUG,"iptable_lock lock \n");
	nmp_mutex_lock(&dns_iptables_lock);
	
	handle = iptc_init("filter");
	if (!handle) {
		dnss_printf(DNSS_ERROR,"dns_iptable_del_interface_filter_commit iptc_init error:%s\n", iptc_strerror(errno));
		goto return_line;
	}
	
/* iptables -D $CP_FILTER -i ${CP_IF} -j ${CP_FILTER_AUTH_IF} */
	intf_info.chain = CP_DNSS;
	intf_info.intf_flag= DNS_INTERFACE_IN;
	intf_info.intf = intf;
	intf_info.target = cap_auth_intf_chain;
	entry = dns_add_del_intf_entry(&intf_info);
	mask = iptable_mask(entry->next_offset);
	ret = iptc_delete_entry(intf_info.chain, entry, mask, handle);
	if (!ret) {
		dnss_printf(DNSS_ERROR,"dns_iptable_del_interface_filter_commit iptc_delete_entry %s error:%s\n", 
								intf_info.chain, iptc_strerror(errno));
		goto return_line;
	}
	free(entry);
	entry = NULL;
	free(mask);
	mask = NULL;
	
	if(DNS_IPTABLES_FREE == type)
	{
		/* iptables -F ${CP_FILTER_AUTH_IF} */
		ret = iptc_flush_entries(cap_auth_intf_chain, handle);
		if (!ret) 
		{
			dnss_printf(DNSS_DEBUG,"dns_iptable_del_interface_filter_commit iptc_flush_entries %s error:%s\n", 
									cap_auth_intf_chain, iptc_strerror(errno));
			goto return_line;
		}
		
		dnss_printf(DNSS_INFO,"iptc_delete_chain %s\n",cap_auth_intf_chain);
	/* iptables -t nat -X ${CP_NAT_AUTH_IF} */
		ret = iptc_delete_chain(cap_auth_intf_chain, handle);
		if (!ret)
		{
			dnss_printf(DNSS_ERROR,"eag_iptable_del_interface_filter_commit iptc_delete_chain %s error:%s\n", 
								cap_auth_intf_chain, iptc_strerror(errno));
			goto return_line;
		}
	}

	ret = iptc_commit(handle);
	if (!ret) {
		dnss_printf(DNSS_DEBUG,"dns_iptable_add_interface_filter_commit iptc_commit:%s\n", iptc_strerror(errno));
	}
	
return_line:
	if (NULL != entry) {
		free(entry);
		entry = NULL;
	}
	if (NULL != handle) {
		iptc_free(handle);
		handle = NULL;
	}
	if (NULL != mask) {
		free(mask);
		mask = NULL;
	}
	
#if USE_THREAD_LOCK	
	pthread_mutex_unlock( &dns_iptables_glock );
	dnss_printf(DNSS_DEBUG,"dns_iptable_glock unlock\n");
#endif
	/*use iptable unlock*/
	nmp_mutex_unlock(&dns_iptables_lock);
	dnss_printf(DNSS_DEBUG,"iptable_lock unlock\n");
	
	return ret;
}


int dns_iptable_del_interface_nat_commit(char * intf,int domain_id,int type)
{
	char cap_nat_default_chain[DNS_IPTABLES_MAXNAMESIZE] = {0};		//CP_NAT_DEFAULT
	snprintf(cap_nat_default_chain, DNS_IPTABLES_MAXNAMELEN, "DNSS_DNAT_%d",domain_id);


	struct iptc_handle *handle = NULL;
	struct ipt_entry *entry = NULL;
	struct dns_intf_entry_info intf_info = {0};
	unsigned char *mask = NULL;
	int ret = 0;

#if USE_THREAD_LOCK	
	dnss_printf(DNSS_DEBUG,"dns_iptable_glock lock\n");
	pthread_mutex_lock( &dns_iptables_glock );
#endif
	/*use iptables lock*/
	dnss_printf(DNSS_DEBUG,"iptable_lock lock \n");
	nmp_mutex_lock(&dns_iptables_lock);
	
	handle = iptc_init("nat");
	if (!handle) {
		dnss_printf(DNSS_ERROR,"eag_iptable_del_interface_filter_commit iptc_init error:%s\n", iptc_strerror(errno));
		goto return_line;
	}

/* iptables -t nat -D CP_DNAT -i ${CP_IF} -j $CP_NAT_DEFAULT */
	intf_info.chain = DNSS_DNAT;
	intf_info.intf_flag = DNS_INTERFACE_IN;
	intf_info.intf = intf;
	intf_info.target = cap_nat_default_chain;
	entry = dns_add_del_intf_entry(&intf_info);
	mask = iptable_mask(entry->next_offset);
	ret = iptc_delete_entry(intf_info.chain, entry, mask, handle);
	if (!ret) {
		dnss_printf(DNSS_DEBUG,"dns_iptable_del_interface_nat_commit iptc_delete_entry %s error:%s\n", 
								intf_info.chain, iptc_strerror(errno));
		goto return_line;
	}
	free(entry);
	entry = NULL;
	free(mask);
	mask = NULL;
	
	if(DNS_IPTABLES_FREE == type)
	{
		/* iptables -t nat -F ${CP_NAT_AUTH_IF} */
		ret = iptc_flush_entries(cap_nat_default_chain, handle);
		if (!ret) {
			dnss_printf(DNSS_ERROR,"eag_iptable_del_interface_filter_commit iptc_flush_entries %s error:%s\n", 
									cap_nat_default_chain, iptc_strerror(errno));
			goto return_line;
		}
		/* iptables -t nat -X ${CP_NAT_AUTH_IF} */
		ret = iptc_delete_chain(cap_nat_default_chain, handle);
		if (!ret) {
			dnss_printf(DNSS_ERROR,"eag_iptable_del_interface_filter_commit iptc_delete_chain %s error:%s\n", 
								cap_nat_default_chain, iptc_strerror(errno));
			goto return_line;
		}
	}
	ret = iptc_commit(handle);
	if (!ret) {
		dnss_printf(DNSS_ERROR,"dns_iptable_add_interface_nat_commit iptc_commit:%s\n", iptc_strerror(errno));
	}
	
return_line:
	if (NULL != entry) {
		free(entry);
		entry = NULL;
	}
	if (NULL != handle) {
		iptc_free(handle);
		handle = NULL;
	}
	if (NULL != mask) {
		free(mask);
		mask = NULL;
	}
	
#if USE_THREAD_LOCK	
	pthread_mutex_unlock( &dns_iptables_glock );
#endif
	/*use iptable unlock*/
	nmp_mutex_unlock(&dns_iptables_lock);
	return ret;
}


int dns_iptable_del_interface(char *intf,int domain_id,int type)
{
	int ret = 0;

	ret = dns_iptable_del_interface_filter_commit(intf, domain_id, type);
	if (!ret) {
		dnss_printf(DNSS_ERROR,"dns_iptable_del_interface_filter_commit error:ret=%d\n", ret);
		return DNS_ERR_UNKNOWN;
	}
	ret = dns_iptable_del_interface_nat_commit(intf, domain_id,type);
	if (!ret) {
		dnss_printf(DNSS_ERROR,"dns_iptable_del_interface_nat_commit error:ret=%d\n", ret);
	    return DNS_ERR_UNKNOWN;
	}
	
	return DNS_RETURN_OK;
}



