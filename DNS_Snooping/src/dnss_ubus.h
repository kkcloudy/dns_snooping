#ifndef _DNSS_UBUS_H_
#define _DNSS_UBUS_H_

#include <libubox/avl.h>
#include <libubus.h>
#include "common.h"
#include "list.h"

struct dnss_interfaces;

#define PROFILE_ITEM_LEN  128
#define MAX_IF_NAME_LEN   16
#define IP_ADDRESS_LEN    32
#define MAX_IPTABLES_LIST 1024
#define FILTER_NAME_LENTH  15


struct white_domain_t{
	struct dl_list node;
	int flag;
	char *domain_name;
};


struct access_role_profile_t{
	struct dl_list node;
	struct dl_list domains_head;
    char name[PROFILE_ITEM_LEN];
	char intf[MAX_IF_NAME_LEN];
	int redirect_status;
	int maping_type;
	int vlan_id;
	int vpn_id;
	char far_end_ip[IP_ADDRESS_LEN];
	char *domain_concents;
};

struct dns_profile{
	struct access_role_profile_t access_role_profile_head;
};


int dnss_ubus_init(struct dnss_interfaces *iface);
void dnss_ubus_fini(struct dnss_interfaces *iface);
void dns_init_list(void);
void dns_profile_list_destroy(void);
int dns_module_restart(void);
int dns_get_domain_id(char *domain_name);
int dns_read_walled_garden_config(void);


#endif
