#include <json-c/json.h>
#include <assert.h>
#include <string.h>
#include "includes.h"
#include "common.h"
#include "eloop.h"
#include "debug.h"
#include <sys/un.h>
#include <netdb.h>  
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <libubox/blobmsg_json.h>
#include "dnss_ubus.h"
#include "dns_snooping.h"
#include "common.h"
#include "dns_iptables.h"
#include "cache.h"
static struct ubus_context *ctx;
struct dns_profile *gloable_agm_profle;

char *domain_p[MAX_IPTABLES_LIST];
char filter_name[MAX_IPTABLES_LIST][FILTER_NAME_LENTH];
char nat_filter_name[MAX_IPTABLES_LIST][FILTER_NAME_LENTH];

#define FILTER_INTF "br-vlan"
#define TUNNEL_INF  "br-"
enum
{
	DNS_ADD,
	DNS_DEL
};

enum
{
	MAPING_TYPE_VLAN = 1,  
	MAPING_TYPE_TUNNEL
};
	
enum
{
	REDIR_ENABLE =1,
	REDIR_DISABLE
};

enum {
	PROFILE_MSG,
	__PROFILE_MAX
};
enum {
	IP_ADDRESS,
	INTERFACE,
	__IPTABLES_MAX
};


static const struct blobmsg_policy dns_profile_policy[] = {
	[PROFILE_MSG] = { .name = "contents", .type = BLOBMSG_TYPE_STRING },
};
	
static const struct blobmsg_policy delete_profile_policy[] = {
	[PROFILE_MSG] = { .name = "name", .type = BLOBMSG_TYPE_STRING },
};
static const struct blobmsg_policy walled_garden_policy[] = {
	[PROFILE_MSG] = { .name = "domain_name", .type = BLOBMSG_TYPE_STRING },
};

static const struct blobmsg_policy dns_iptables_rule[] = {
	[IP_ADDRESS] = { .name = "ip", .type = BLOBMSG_TYPE_INT32 },
	[INTERFACE] = { .name = "intf", .type = BLOBMSG_TYPE_STRING },
};
/*
struct white_domain_t{
	struct dl_list node;
	int flag;
	char *domain_name;
};
*/
static void dnss_ubus_reply(struct ubus_request_data *req, int result)
{
	static struct blob_buf b;
	struct ubus_request_data new_req;
    char *arr[2] = {"success", "failed"};

    assert(req != NULL);
	ubus_defer_request(ctx, req, &new_req);

	blob_buf_init(&b, 0);
	blobmsg_add_string(&b, "status", arr[result]);
    ubus_send_reply(ctx, &new_req, b.head);
	ubus_complete_deferred_request(ctx, &new_req, 0);

	return;
}

void show_arp(void)
{
	struct access_role_profile_t *profile;
	struct white_domain_t *domain;
	dl_list_for_each(profile,&(gloable_agm_profle->access_role_profile_head.node),struct access_role_profile_t, node)
	{
		dnss_printf(DNSS_DEBUG,"----------------------------------------------------------------\n");
		dnss_printf(DNSS_DEBUG,"role_name %s : intf:%s\n",profile->name,profile->intf);
		dl_list_for_each(domain,&(profile->domains_head),struct white_domain_t, node)
		{
			dnss_printf(DNSS_DEBUG,"domain_name %s\n",domain->domain_name);
		}
		dnss_printf(DNSS_DEBUG,"----------------------------------------------------------------\n");
	}
	return;
}

static int show_domain_id(void)
{
	int i;
	dnss_printf(DNSS_INFO,"Display all domain ID\n");
	for(i=0; i<MAX_IPTABLES_LIST; i++)
	{
		if(NULL != domain_p[i])
		{
			dnss_printf(DNSS_INFO,"domain[%d]:%s\n",i,domain_p[i]);
		}
	}
	return 0;
}

static int dnss_ubus_show_domain_id(struct ubus_context *ctx, struct ubus_object *obj,
                             		   struct ubus_request_data *req, const char *method,
                             		   struct blob_attr *msg)
{
	int result = 0;
    dnss_printf(DNSS_DEBUG, "dnss_ubus recv get msg, method = %s\n", method);
	show_domain_id();
    dnss_ubus_reply(req, result);

	return 0;
}

static int dnss_ubus_show_arp(struct ubus_context *ctx, struct ubus_object *obj,
                             		   struct ubus_request_data *req, const char *method,
                             		   struct blob_attr *msg)
{
	int result = 0;
    dnss_printf(DNSS_DEBUG, "dnss_ubus recv get msg, method = %s\n", method);
	show_arp();
    dnss_ubus_reply(req, result);

	return 0;
}


static int dnss_ubus_show_cache(struct ubus_context *ctx, struct ubus_object *obj,
                             		   struct ubus_request_data *req, const char *method,
                             		   struct blob_attr *msg)
{
	int result = 0;
    dnss_printf(DNSS_DEBUG, "dnss_ubus recv get msg, method = %s\n", method);
	cache_printf();
    dnss_ubus_reply(req, result);

	return 0;
}

static int dnss_ubus_del_cache(struct ubus_context *ctx, struct ubus_object *obj,
                             		   struct ubus_request_data *req, const char *method,
                             		   struct blob_attr *msg)
{
	char name[32] = {"www.baidu.com"};
	int result = 0;
    dnss_printf(DNSS_DEBUG, "dnss_ubus recv get msg, method = %s\n", method);
	cache_delete(name);
    dnss_ubus_reply(req, result);
	
	return 0;
}



struct access_role_profile_t *dns_access_role_profile_find_by_name(struct dl_list *head,const char * name)
{
	if ( NULL == name ||  NULL == head )
	{
		dnss_printf(DNSS_ERROR,"dns_access_role_profile_find_by_name:parameters err\n");
		return NULL;
	}
	struct access_role_profile_t *profile;
	dl_list_for_each(profile,head,struct access_role_profile_t, node)
	{
		if ( !strcmp(name,profile->name))
			return profile;
	}
	return NULL;
}

struct access_role_profile_t* dns_access_role_profile_new()
{
	struct access_role_profile_t *new_profile = NULL;
	new_profile = malloc(sizeof(struct access_role_profile_t));
	if ( NULL == new_profile )
	{
		dnss_printf(DNSS_ERROR,"dns_access_role_profile_new :malloc fail\n");
		return NULL;
	}
	memset(new_profile,0,sizeof(struct access_role_profile_t));
	dl_list_init(&(new_profile->domains_head));
	return new_profile;
}

static int eag_get_tunnel_interface_name(struct access_role_profile_t *access_role, char *name)
{
	char cmd[256] = {0};
	char buf[1024] = {0};
	FILE *fp = NULL;
	char * str_temp  = NULL;
	char * str_temp2 = NULL;
	snprintf( cmd, sizeof(cmd)-1, "ubus call l2gre search '{\"tunnelID\":%d, \"remoteIP\":\"%s\"}'",access_role->vpn_id,access_role->far_end_ip);
	fp = popen( cmd, "r" );
	if(NULL != fp)
	{
		fread( buf, sizeof(char), 1024,  fp);
	    str_temp = strstr(buf, "g");
		if (NULL != str_temp)
		{
			str_temp2 = strtok(str_temp, "\"");
			strcpy(name,str_temp2);
		}
		dnss_printf(DNSS_INFO,"get intf %s\n",name);
	}
	pclose(fp);
	dnss_printf(DNSS_INFO,"get tunnel intf name %s tunnel id %d farEndip %s cmd %s\n",name,access_role->vpn_id,access_role->far_end_ip,cmd);
	return 0;
}

static int dns_get_intf( struct access_role_profile_t *profile)
{
	char tunnel_name[20] ={0};
	if(MAPING_TYPE_VLAN == profile->maping_type)
	{
		if ( 0 == profile->vlan_id)
			strcpy(profile->intf,"br-wan");
		else
			sprintf(profile->intf,FILTER_INTF"%d", profile->vlan_id);
	}
	
	if(MAPING_TYPE_TUNNEL == profile->maping_type)
	{
		eag_get_tunnel_interface_name(profile, tunnel_name);
		sprintf(profile->intf,TUNNEL_INF"%s",tunnel_name);
	}
	dnss_printf(DNSS_INFO,"get intf %s\n",profile->intf);
	return 0;
}

static struct white_domain_t *dns_create_new_domain()
{
	struct white_domain_t *new_domain = NULL;
	new_domain = malloc(sizeof(struct white_domain_t));
	if ( NULL == new_domain )
	{
		dnss_printf(DNSS_ERROR,"dns_create_new_domain :new_domain malloc fail\n");
		return NULL;
	}
	memset(new_domain,0,sizeof(struct white_domain_t));

	return new_domain;
}

static int dns_find_domain_in_all_profile(char *domain_name,char *intf,char *role_name)
{
	struct access_role_profile_t *profile;
	struct white_domain_t *domain;
	dl_list_for_each(profile,&(gloable_agm_profle->access_role_profile_head.node),struct access_role_profile_t, node)
	{
		dl_list_for_each(domain,&(profile->domains_head),struct white_domain_t, node)
		if((0 == strcmp(domain_name,domain->domain_name))&&
		   (0== strcmp(profile->intf,intf))&&
		   (strcmp(profile->name,role_name)))
		{
			dnss_printf(DNSS_DEBUG,"find domain name exsit role% s domain_name %s\n",profile->name,domain->domain_name);
			return 1;
		}
	}

	return 0;
}

static int dns_is_del_iptables_intf(char *domain_name, char *intf, char *role_name)
{
	struct access_role_profile_t *profile;
	struct white_domain_t *domain;
	dl_list_for_each(profile,&(gloable_agm_profle->access_role_profile_head.node),struct access_role_profile_t, node)
	{
		dl_list_for_each(domain,&(profile->domains_head),struct white_domain_t, node)
		if((0 == strcmp(domain_name,domain->domain_name))&&
		   (0==strcmp(profile->intf,intf))&&
		   (strcmp(profile->name,role_name)))
			return 1;
	}

	return 0;
}

static int dns_iptables_filter_free(char *domain_name)
{
	struct access_role_profile_t *profile;
	struct white_domain_t *domain;
	dl_list_for_each(profile,&(gloable_agm_profle->access_role_profile_head.node),struct access_role_profile_t, node)
	{
		dl_list_for_each(domain,&(profile->domains_head),struct white_domain_t, node)
		if(0 == strcmp(domain_name,domain->domain_name))
			return 0;
	}
	return 1;
}

int dns_get_domain_id(char *domain_name)
{
	int i;
	int j=0;
	for(i=0; i<MAX_IPTABLES_LIST; i++)
	{
		if(domain_p[i] != NULL )
		{
			if(0 == strcmp(domain_name,domain_p[i]))
			{
				dnss_printf(DNSS_DEBUG,"add domain[%d]:%s\n",i,domain_p[i]);
				return i;
			}
		}
	}
	
	if(MAX_IPTABLES_LIST == i)
	{
		for(j=0;j<MAX_IPTABLES_LIST;j++)
		{
			if(NULL == domain_p[j])
			{
				dnss_printf(DNSS_DEBUG,"find domian id %d\n",j);
				return j;
			}
		}
	}
	
	if(MAX_IPTABLES_LIST == j)
	{
		dnss_printf(DNSS_ERROR,"don't have free id\n");
		return -1;
	}
	
}

void url_to_hexurl(char *url,char *hexurl)
{
   if( url == NULL || hexurl == NULL)
	   return ;
   char *token;
   int rlen=0;
   int i = 0;
   int j = 0,len =0;
   char hex[16]={'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};
   char *cmd[10];

   for (token = strtok(url, "."); token; token = strtok(NULL, ".")) 
   {
	   cmd[i]=token;
	   i++;
   }
   while( j < i)
   {
	   hexurl[len] = hex[strlen(cmd[j])/16];
	   hexurl[len+1] = hex[strlen(cmd[j])%16];
	   len +=2;
	   for(rlen = 0; rlen < strlen(cmd[j]); rlen++)
	   {
		   hexurl[len] = hex[cmd[j][rlen]/16];
		   hexurl[len+1] = hex[cmd[j][rlen]%16];
		   len +=2; 	   
		   
	   }
	   j++;

   }
   dnss_printf(DNSS_DEBUG,"hexurl %s\n",hexurl);
   return ;  
}

static int dns_add_iptables_nfqueue_rule(char *domain_name,int type)
{
	char hexurl[1024]={0};
	char rule_cmd[1500]={0};
	char buf[256]={0};
	FILE *fp = NULL;
	strncpy(buf,domain_name,255);
	url_to_hexurl(buf, hexurl);
	memset(buf,0,sizeof(buf));
	strncpy(buf,hexurl,240);
	if(DNS_ADD == type)
	{
		snprintf(rule_cmd,sizeof(rule_cmd)-1,"iptables -I CP_DNSS -p udp --sport 53 -m string"\
			" --hex-string '|%s|' --algo bm --from 0 --to 65535 -j NFQUEUE --queue-num 1000",buf);
	}
	if(DNS_DEL == type)
	{
		snprintf(rule_cmd,sizeof(rule_cmd)-1,"iptables -D CP_DNSS -p udp --sport 53 -m string"\
			" --hex-string '|%s|' --algo bm --from 0 --to 65535 -j NFQUEUE --queue-num 1000",buf);
	}
	fp = popen(rule_cmd, "r" );
	pclose(fp);
	dnss_printf(DNSS_DEBUG,"create nfqueue rule cmd [%s]\n",rule_cmd);
	return 0;
}

static int dns_add_del_filter_intf(char *domain_name, struct access_role_profile_t *profile,int type)
{
	int domain_id;
	if(strlen(domain_name) > 255)
		return 0;
	domain_id = dns_get_domain_id(domain_name);
	dnss_printf(DNSS_DEBUG,"find domain id %d\n",domain_id);
	if(domain_id < 0)
		return 0;
	if(DNS_ADD == type)
	{
		if(0== dns_find_domain_in_all_profile(domain_name, profile->intf,profile->name))
		{
			dnss_printf(DNSS_INFO,"dns_iptable_add_interface intf %s, id %d domain_name %s\n",profile->intf, domain_id,domain_name);
			dns_iptable_add_interface(profile->intf, domain_id);
			if(NULL == domain_p[domain_id])
				dns_add_iptables_nfqueue_rule(domain_name,DNS_ADD);
			if(domain_p[domain_id] == NULL)
			{
				domain_p[domain_id]= malloc(strlen(domain_name)+1);
				if(NULL !=domain_p[domain_id])
				{
					memset(domain_p[domain_id],0,strlen(domain_name)+1);
					strcpy(domain_p[domain_id],domain_name);
				}
			}
		}	
	}
	if(DNS_DEL == type)
	{
		if(dns_iptables_filter_free(domain_name))
		{
			dnss_printf(DNSS_INFO,"dns_iptables_filter_free %s\n",domain_name);
			dns_add_iptables_nfqueue_rule(domain_name,DNS_DEL);
			dns_iptable_del_interface(profile->intf,domain_id,DNS_IPTABLES_FREE);
			cache_delete(domain_name);
			if(NULL != domain_p[domain_id])
			{
				free(domain_p[domain_id]);
				domain_p[domain_id]=NULL;
			}
			return 0;
		}
		if(0==dns_is_del_iptables_intf(domain_name,profile->intf,profile->name))
		{
			dnss_printf(DNSS_INFO,"dns_is_del_iptables_intf %s\n",domain_name);
			dns_iptable_del_interface(profile->intf,domain_id,DNS_IPTABLES_REMOVE);
		}

	}
	return 0;
}

static int dns_get_each_domian(struct access_role_profile_t *profile,struct json_object *domian_obj)
{
	struct json_object *obj;
	const char *buf = NULL;
	struct white_domain_t *domain = NULL; 
	int i;
	int domain_id;
	if(!json_object_is_type(domian_obj, json_type_array))
	{
		dnss_printf(DNSS_ERROR,"access role profile format err,please check\n");
		return -1;
	}
	
	for(i=0; i < json_object_array_length(domian_obj); i++)
	{
		obj = json_object_array_get_idx(domian_obj, i);
		buf = json_object_get_string(obj);
		domain = dns_create_new_domain();
		domain->domain_name = malloc(strlen(buf)+1);
		if(NULL != domain->domain_name)
		{
			memset(domain->domain_name,0,(strlen(buf)+1));
			strcpy(domain->domain_name,buf);
			dnss_printf(DNSS_INFO,"add one domain %s\n",domain->domain_name);
			domain->flag = 1;
			dns_add_del_filter_intf(domain->domain_name, profile,DNS_ADD);
			dl_list_add_tail(&(profile->domains_head), &(domain->node));
		}
	}
	return 0;
}

static int dns_find_domain_in_profile(struct dl_list *head, const char *buf)
{
	if ( NULL == head )
	{
		dnss_printf(DNSS_ERROR,"parameters err\n");
		return NULL;
	}
	struct white_domain_t  *domain;
	struct white_domain_t  *next;
	dl_list_for_each_safe(domain,next,head,struct white_domain_t, node)
	{
		if(NULL != domain)
		{
			if(0 == strcmp(domain->domain_name,buf))
			{
				domain->flag = 0;
				return 1;
			}
		}
	}
	return 0;
}

static int dns_compare_differ_domain(struct access_role_profile_t *profile,struct json_object *domian_obj)
{
	struct json_object *obj;
	const char *buf = NULL;
	struct white_domain_t *domain = NULL; 
	int i;
	if(!json_object_is_type(domian_obj, json_type_array))
	{
		dnss_printf(DNSS_ERROR,"access role profile format err,please check\n");
		return -1;
	}
	for(i=0; i < json_object_array_length(domian_obj); i++)
	{
		obj = json_object_array_get_idx(domian_obj, i);
		buf = json_object_get_string(obj);
		if(0 == dns_find_domain_in_profile(&(profile->domains_head),buf))
		{
			domain = dns_create_new_domain();
			domain->domain_name = malloc(strlen(buf)+1);
			if(NULL != domain->domain_name)
			{
				memset(domain->domain_name,0,(strlen(buf)+1));
				strcpy(domain->domain_name,buf);
				dnss_printf(DNSS_INFO,"dns_compare_differ_domain add one domain %s\n",domain->domain_name);
				dns_add_del_filter_intf(domain->domain_name, profile,DNS_ADD);
				dl_list_add_tail(&(profile->domains_head), &(domain->node));
			}
		}

	}
	return 0;
}


static int dns_domian_list_destroy(struct dl_list *head)
{
	if ( NULL == head )
	{
		dnss_printf(DNSS_ERROR,"dns_domian_list_destroy:parameters err\n");
		return NULL;
	}
	struct white_domain_t  *domain;
	struct white_domain_t  *next;
	dl_list_for_each_safe(domain,next,head,struct white_domain_t, node)
	{
		if(NULL != domain)
		{
			dl_list_del(&(domain->node));
			if(NULL != domain->domain_name)
			{
				free(domain->domain_name);
				domain->domain_name = NULL;
			}
			free(domain);
			domain = NULL;
		}
	}
	dnss_printf(DNSS_INFO,"free access role profile success\n");
	return NULL;

}

static void *dns_domian_list_free(struct access_role_profile_t *profile)
{
	int domain_id;
	struct dl_list *head = &(profile->domains_head);
	if ( NULL == head )
	{
		dnss_printf(DNSS_ERROR,"parameters err\n");
		return NULL;
	}
	struct white_domain_t  *domain;
	struct white_domain_t  *next;
	dl_list_for_each_safe(domain,next,head,struct white_domain_t, node)
	{
		if(NULL != domain)
		{
			dl_list_del(&(domain->node));
			if(NULL != domain->domain_name)
			{
				dns_add_del_filter_intf(domain->domain_name,profile,DNS_DEL);
				free(domain->domain_name);
				domain->domain_name = NULL;
			}
			free(domain);
			domain = NULL;
		}
	}
	dnss_printf(DNSS_INFO,"free access role profile success\n");
	return NULL;
}

static void *dns_domian_list_flag_free(struct access_role_profile_t *profile)
{
	int ret;
	int domain_id;
	struct dl_list *head=&(profile->domains_head);
	if ( NULL == head )
	{
		dnss_printf(DNSS_ERROR,"parameters err\n");
		return NULL;
	}
	struct white_domain_t  *domain;
	struct white_domain_t  *next;
	dl_list_for_each_safe(domain,next,head,struct white_domain_t, node)
	{
		if(NULL != domain)
		{
			if(1 == domain->flag)
			{
				dl_list_del(&(domain->node));
				if(NULL != domain->domain_name)
				{
					dns_add_del_filter_intf(domain->domain_name, profile, DNS_DEL);
					dnss_printf(DNSS_INFO,"free domain %s success\n",domain->domain_name);
					free(domain->domain_name);
					domain->domain_name = NULL;
				}
				free(domain);
				domain = NULL;
			}
			else
				domain->flag=1;
		}
	}
	
	return NULL;
}

static int dns_get_info_from_profile(struct access_role_profile_t *profile, struct access_role_profile_t *profile_new)
{
	profile->maping_type = profile_new->maping_type;
	profile->vlan_id = profile_new->vlan_id;
	profile->vpn_id = profile_new->vpn_id;
	dns_get_intf(profile);
	return 0;
}

static int dns_list_free_for_diff_intf(struct access_role_profile_t *profile, char *intf)
{
	struct white_domain_t *domain;
	 
	dl_list_for_each(domain,&(profile->domains_head),struct white_domain_t, node)
	{ 
		dns_add_del_filter_intf(domain->domain_name,profile,DNS_DEL);
	}
	
	strcpy(profile->intf,intf); 
	dl_list_for_each(domain,&(profile->domains_head),struct white_domain_t, node)
	{
		dns_add_del_filter_intf(domain->domain_name,profile,DNS_ADD);
	}
	return 0;
}

int add_access_role_profile(char *msgstr)
{
	struct json_object *json_obj = NULL;
	struct json_object *result = NULL;
	struct json_object *domian_obj = NULL;
	const char *domain_str = NULL;
	struct access_role_profile_t profile_new ;
	struct access_role_profile_t *profile = NULL;
	int domain_lenth = 0;
	dnss_printf(DNSS_INFO,"receive contents: %s\n",msgstr);
	
	json_obj = json_tokener_parse(msgstr);

   	if (0==json_object_object_get_ex(json_obj,"name",&result))
	{
		dnss_printf(DNSS_ERROR,"json_object_object_get name no exist\n");
	  	goto err_free;
   	}
	else 
	{
	    if(NULL != result)
			strcpy(profile_new.name,json_object_get_string(result));
	}
	
	if (0==json_object_object_get_ex(json_obj,"mappingType",&result))
	{
	    dnss_printf(DNSS_ERROR,"json_object_object_get mappingType no exist\n");
		goto err_free;
	}
	else 
	{
		if(NULL != result)
		{
			if( 0 == strcasecmp(json_object_get_string(result),"Vlan"))
			{
				profile_new.maping_type = MAPING_TYPE_VLAN;
				if (0==json_object_object_get_ex(json_obj,"vlanNumber",&result))
				{
					dnss_printf(DNSS_ERROR,"json_object_object_get vlanNumber no exist\n");
		 			goto err_free;
				}
				else
				{
					 if(NULL != result)
					 	profile_new.vlan_id = json_object_get_int(result);
				}
			}
			if(0 == strcmp(json_object_get_string(result),"Tunnel"))
			{
				profile_new.maping_type = MAPING_TYPE_TUNNEL;
				if (0==json_object_object_get_ex(json_obj,"vpnID",&result))
				{
					dnss_printf(DNSS_ERROR,"json_object_object_get vpnID no exist\n");
		 			goto err_free;
				}
				else
				{
					 if(NULL != result)
					 	profile_new.vpn_id= json_object_get_int(result);
				}
				
				if (0==json_object_object_get_ex(json_obj,"farEndIP",&result))
				{
					dnss_printf(DNSS_ERROR,"json_object_object_get farEndIP no exist\n");
		 			goto err_free;
				}
				else
				{
					 if(NULL != result)
					 	strcpy(profile_new.far_end_ip,json_object_get_string(result));
				}
			}
		}
	}
	
   	if (0==json_object_object_get_ex(json_obj,"wListDomains",&domian_obj))
	{
		dnss_printf(DNSS_ERROR,"json_object_object_get wListDomains no exist\n");
	  	goto err_free;
   	}
	else 
	{
	    if(NULL != domian_obj)
	    {
			domain_str = json_object_to_json_string_ext(domian_obj,JSON_C_TO_STRING_PRETTY);
			domain_lenth = strlen(domain_str);
			dnss_printf(DNSS_INFO,"receive wListDomains %s\n",domain_str);
	    }
	}
	
	profile = dns_access_role_profile_find_by_name(&(gloable_agm_profle->access_role_profile_head.node),profile_new.name);
	
	if(NULL == profile)
	{
		profile = dns_access_role_profile_new();
		if( NULL == profile)
		{
			dnss_printf(DNSS_ERROR,"malloc profile fail\n");
			goto err_free;
		}
		strcpy(profile->name,profile_new.name);
		dnss_printf(DNSS_ERROR,"profile name %s\n",profile->name);
		profile->domain_concents = malloc(domain_lenth +1);
		if(NULL == profile->domain_concents)
		{
			dnss_printf(DNSS_ERROR,"malloc domain_concents fail\n");
			goto err_free_1;
		}
		memset(profile->domain_concents,0,domain_lenth +1);
		strcpy(profile->domain_concents,domain_str);
		dns_get_info_from_profile(profile,&profile_new);
		dns_get_each_domian(profile,domian_obj);
		dl_list_add_tail(&(gloable_agm_profle->access_role_profile_head.node),&(profile->node));
	}
	else
	{
		dnss_printf(DNSS_INFO,"profile->domain_concents %s\n domain_str:%s\n",profile->domain_concents,domain_str);
		if(strcmp(profile->domain_concents,domain_str))
		{
			free(profile->domain_concents);
			profile->domain_concents = malloc(domain_lenth +1);
			if(NULL == profile->domain_concents)
			{
				dnss_printf(DNSS_ERROR,"malloc domain_concents fail\n");
				goto err_free;
			}
			memset(profile->domain_concents,0,domain_lenth +1);
			strcpy(profile->domain_concents,domain_str);
			dns_compare_differ_domain(profile,domian_obj);
			dns_domian_list_flag_free(profile);
		}
		
		if((0==strcmp(profile->domain_concents,domain_str))&&
		  	(0==strcmp(profile_new.intf,profile->intf)))
		{
			dnss_printf(DNSS_INFO,"domain_concents already exit\n");
			json_object_put(json_obj);
			return 0;
		}
		 dns_get_intf(&(profile_new));
		if(strcmp(profile_new.intf,profile->intf))
		{
			dns_list_free_for_diff_intf(profile,profile_new.intf);
		}
		dns_get_info_from_profile(profile,&profile_new);
	}

	json_object_put(json_obj);
	return 0;
	
	
err_free_1:
	free(profile);
	profile = NULL;
	
err_free:
	json_object_put(json_obj);
	return 0;
}

static int dns_create_access_role_profile(struct ubus_context *ctx, struct ubus_object *obj,
								   struct ubus_request_data *req, const char *method,
									struct blob_attr *msg)
{
	struct blob_attr *tb[__PROFILE_MAX];
	int result = 0;
	char *msgstr = "(unknown)";
	
	blobmsg_parse(dns_profile_policy, ARRAY_SIZE(dns_profile_policy), tb, blob_data(msg), blob_len(msg));
    if (tb[PROFILE_MSG])
	{
		msgstr = blobmsg_data(tb[PROFILE_MSG]);
		result = add_access_role_profile(msgstr);
    }
    dnss_ubus_reply(req, result);		
	return 0;
}

int delete_access_role_profile(const char *profile_name)
{
	struct access_role_profile_t *profile = NULL;
	dnss_printf(DNSS_INFO,"receive name: %s\n",profile_name);
	profile = dns_access_role_profile_find_by_name(&(gloable_agm_profle->access_role_profile_head.node),profile_name);
	if(NULL != profile)
	{
		dl_list_del(&(profile->node));
		dns_domian_list_free(profile);
		if(NULL != profile->domain_concents)
		{
			free(profile->domain_concents);
			profile->domain_concents = NULL;
		}
		
		free(profile);
		profile = NULL;
		dnss_printf(DNSS_INFO,"delete_access_role_profile success\n");
	}
	return 0;	
}

static int dns_delete_access_role_profile(struct ubus_context *ctx, struct ubus_object *obj,
								   struct ubus_request_data *req, const char *method,
									struct blob_attr *msg)
{
	struct blob_attr *tb[__PROFILE_MAX];

	const char *msgstr = "(unknown)";
	int result =0;
	
	blobmsg_parse(delete_profile_policy, ARRAY_SIZE(delete_profile_policy), tb, blob_data(msg), blob_len(msg));
    if (tb[PROFILE_MSG])
	{
		msgstr = blobmsg_data(tb[PROFILE_MSG]);
		result =delete_access_role_profile(msgstr);
    }
	dnss_ubus_reply(req, result);
	return 0;
}

static int dns_find_domain_name(char *name)
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

static int dns_create_walled_garden(struct ubus_context *ctx, struct ubus_object *obj,
								   	struct ubus_request_data *req, const char *method,
									struct blob_attr *msg)
{
	struct blob_attr *tb[__PROFILE_MAX];
	char *domain_name = NULL;
	int result =1;
	int domain_id;
	char *intf =NULL;
	blobmsg_parse(walled_garden_policy, ARRAY_SIZE(walled_garden_policy), tb, blob_data(msg), blob_len(msg));
	if(tb[PROFILE_MSG])
	{
		domain_name = blobmsg_get_string(tb[PROFILE_MSG]);
	}
	
	if(NULL != domain_name && domain_name[0]!='\0')
	{
		 if(0 == dns_find_domain_name(domain_name))
		 {
		 	dnss_printf(DNSS_INFO, "domain_name %s already exit.\n",domain_name);
			dnss_ubus_reply(req,result);
	   		return 0;	
		 }
		domain_id = dns_get_domain_id(domain_name);
		if(domain_id < 0)
		{
			dnss_printf(DNSS_INFO, "con't get free domain_id.\n");
			dnss_ubus_reply(req,result);
	   		return -1;
		}

		dns_iptable_add_interface(intf, domain_id);
		dns_add_iptables_nfqueue_rule(domain_name, DNS_ADD);
		if(domain_p[domain_id] == NULL)
		{
			domain_p[domain_id]= malloc(strlen(domain_name)+1);
			if(NULL !=domain_p[domain_id])
			{
				memset(domain_p[domain_id],0,strlen(domain_name)+1);
				strcpy(domain_p[domain_id],domain_name);
			}
		}
		
	}
	result = 0;
	dnss_ubus_reply(req,result);
	return 0;
}

static int dns_delete_walled_garden(struct ubus_context *ctx, struct ubus_object *obj,
									struct ubus_request_data *req, const char *method,
									struct blob_attr *msg)
{
	struct blob_attr *tb[__PROFILE_MAX];
	char *domain_name = NULL;
	int result =1;
	int domain_id;
	char *intf =NULL;
	
	blobmsg_parse(walled_garden_policy, ARRAY_SIZE(walled_garden_policy), tb, blob_data(msg), blob_len(msg));
	if(tb[PROFILE_MSG])
	{
		domain_name = blobmsg_get_string(tb[PROFILE_MSG]);
	}
	
	if(NULL != domain_name && domain_name[0]!='\0')
	{
		 if(dns_find_domain_name(domain_name))
		 {
		 	dnss_printf(DNSS_INFO, "domain_name %s don't exit.\n",domain_name);
			dnss_ubus_reply(req,result);
	   		return 0;	
		 }
		domain_id = dns_get_domain_id(domain_name);
		if(domain_id < 0)
		{
			dnss_printf(DNSS_INFO, "con't find domain_id.\n");
			dnss_ubus_reply(req,result);
	   		return -1;
		}
		dns_add_iptables_nfqueue_rule(domain_name, DNS_DEL);
		dns_iptable_del_interface(intf,domain_id,DNS_IPTABLES_FREE);
		cache_delete(domain_name);
		if(NULL != domain_p[domain_id])
		{
			free(domain_p[domain_id]);
			domain_p[domain_id]=NULL;
		}
	}
	
	result = 0;
	dnss_ubus_reply(req,result);
	return 0;
}
									
static const struct ubus_method dnss_global_methods[] = {
	UBUS_METHOD_NOARG("ShowID", dnss_ubus_show_domain_id),
	UBUS_METHOD_NOARG("ShowARP", dnss_ubus_show_arp),
	UBUS_METHOD_NOARG("ShowCache", dnss_ubus_show_cache),
	UBUS_METHOD_NOARG("DelCache", dnss_ubus_del_cache),
	UBUS_METHOD("CREATEAccessRoleProfile",dns_create_access_role_profile,dns_profile_policy),
	UBUS_METHOD("DELETEAccessRoleProfile",dns_delete_access_role_profile,delete_profile_policy),
	UBUS_METHOD("CREATEWalledGarden",dns_create_walled_garden,walled_garden_policy),
	UBUS_METHOD("DELETEWalledGarden",dns_delete_walled_garden,walled_garden_policy),
};

static struct ubus_object_type dnss_global_object_type =
	UBUS_OBJECT_TYPE("dns_snooping", dnss_global_methods);

static void ubus_receive(int sock, void *eloop_ctx, void *sock_ctx)
{
 	struct ubus_context *ctx = eloop_ctx;
 	ubus_handle_event(ctx);
}


int dnss_ubus_init(struct dnss_interfaces *iface)
{
	struct ubus_object *obj = &iface->ubus_obj;
	int ret;

	if(ctx)
		return 1;

	ctx = ubus_connect(NULL);
 	if (!ctx)
 	    return 0;

	eloop_register_read_sock(ctx->sock.fd, ubus_receive, ctx, NULL);

	
	obj->name = "dns_snooping";
	obj->type = &dnss_global_object_type;
	obj->methods = dnss_global_object_type.methods;
	obj->n_methods = dnss_global_object_type.n_methods;

	ret = ubus_add_object(ctx, obj);
	if (ret)
		dnss_printf(DNSS_DEBUG, "DNSS_GLOBAL Failed to add dns snooping global object: %s\n", ubus_strerror(ret));

    return 1;
}

void dns_init_list(void)
{
	gloable_agm_profle = malloc(sizeof(struct dns_profile));
	if(NULL == gloable_agm_profle)
	{
		dnss_printf(DNSS_ERROR,"malloc dns_profile fail\n");
		return;
	}
	memset(gloable_agm_profle, 0, sizeof(struct dns_profile));
	dl_list_init(&(gloable_agm_profle->access_role_profile_head.node));
}

void dns_profile_list_destroy(void)
{
	struct dl_list *head = &(gloable_agm_profle->access_role_profile_head.node);
	if ( NULL == head )
	{
		dnss_printf(DNSS_ERROR,"parameters err\n");
		return NULL;
	}
	struct access_role_profile_t *profile;
	struct access_role_profile_t *next;
	dl_list_for_each_safe(profile,next,head,struct access_role_profile_t, node)
	{
		if(NULL != profile)	
		{
			dl_list_del(&(profile->node));
			dns_domian_list_destroy(&(profile->domains_head));
			if(NULL != profile->domain_concents)
			{
				free(profile->domain_concents);
				profile->domain_concents = NULL;
			}
		
			free(profile);
			profile = NULL;
		}
	}
	
	free(gloable_agm_profle);
	gloable_agm_profle = NULL;
	dnss_printf(DNSS_INFO,"free access role profile success\n");
	return NULL;


}

int dns_module_restart()
{
	char cmd[256] = {0};
	char buf[256] = {0};
	FILE *fp = NULL;
	snprintf( cmd, sizeof(cmd)-1, "ubus call AG-manager modulerestart '{\"name\":\"dns_snooping\"}'");
	fp = popen( cmd, "r" );
	fread( buf, sizeof(char), 256,  fp);
	pclose(fp);
	dnss_printf(DNSS_INFO,"dns_module_restart cmd=%s return=%s\n", cmd, buf);
	return 0;
}

int dns_read_walled_garden_config()
{
	struct json_object *new_obj;
	struct json_object *obj;
	struct json_object *contents;
	struct json_object *domain_obj;
	const char *buf = NULL;
	char *domain = NULL;
	int domain_id;
	char *intf =NULL;
	char * domain_name = NULL;
	int i;
	new_obj = json_object_from_file("/var/config/walledgarden.conf");
	if( NULL == new_obj )
		return NULL;
	if(!json_object_object_get_ex(new_obj,"WalledGarden",&contents))
		return NULL;
	for(i=0; i < json_object_array_length(contents); i++) 
	{
		obj = json_object_array_get_idx(contents, i);
		if(!json_object_object_get_ex(obj,"URL",&domain_obj))
			continue;
		if(NULL == domain_obj)
			continue;
		domain_name = json_object_get_string(domain_obj);
		if(domain_name[0] != '\0')
		{
			domain_id = dns_get_domain_id(domain_name);
			if(domain_id < 0)
			{
				json_object_put(new_obj);
				dnss_printf(DNSS_INFO, "con't get free domain_id.\n");
	   			return NULL;
			}
			dns_add_iptables_nfqueue_rule(domain_name, DNS_ADD);
			dns_iptable_add_interface(intf, domain_id);
			if(domain_p[domain_id] == NULL)
			{
				domain_p[domain_id]= malloc(strlen(domain_name)+1);
				if(NULL !=domain_p[domain_id])
				{
					memset(domain_p[domain_id],0,strlen(domain_name)+1);
					strcpy(domain_p[domain_id],domain_name);
				}
			}
			dnss_printf(DNSS_INFO,"dns_read_walled_garden_config: %s\n",domain_name);
		}
	}	
	json_object_put(new_obj);
	return NULL;
}

void dnss_ubus_fini(struct dnss_interfaces *iface)
{
    struct ubus_object *obj = &iface->ubus_obj;

 	if (!ctx)
 	    return;

 	eloop_unregister_read_sock(ctx->sock.fd);
    ubus_remove_object(ctx, obj);

 	ubus_free(ctx);
 	ctx = NULL;

    return;
}


