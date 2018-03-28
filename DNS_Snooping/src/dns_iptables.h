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
*	RCSfile   :  dns_iptables.h
*
*	Author   :  wangke
*
*	Revision :  1.00
*
*	Date      :  2010-1-5
********************************************************************************/
#ifndef _DNS_IPTABLES_H
#define _DNS_IPTABLES_H

/*********************************************************
*	head files														*
**********************************************************/

/*********************************************************
*	macro define													*
**********************************************************/

#define DNS_IPTABLES_SOURCE 					1
#define DNS_IPTABLES_DESTINATION 				2
#define DNS_IPTABLES_ADD						4
#define DNS_IPTABLES_DELTE				 		5
#define DNS_IPTABLES_MAXNAMESIZE	            32
#define DNS_IPTABLES_MAXNAMELEN	            	30
#define DNS_INTERFACE_IN	1
#define DNS_INTERFACE_OUT	2
#define IP_CHAIN_CREATE                          4
#define DNS_IPTABLES_REMOVE 2
#define DNS_IPTABLES_FREE   3


struct dns_intf_entry_info {
	char *chain;
	char *intf;
	char *setname;
	char *setflag;
	char *target;
	int port;
	int intf_flag;
};


int 
connect_up(const unsigned int user_ip,int domain_id);
int 
connect_down(const unsigned int user_ip,int domain_id);

int dns_iptable_add_interface(char *intf,int domain_id);
int dns_iptable_del_interface(char *intf,int domian_id,int type);


#endif
