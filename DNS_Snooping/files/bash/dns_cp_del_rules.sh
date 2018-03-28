#!/bin/sh
CP_DNAT="DNSS_DNAT"
CP_FILTER="CP_DNSS"

iptables -D FORWARD -j $CP_FILTER
iptables -F $CP_FILTER
iptables -X $CP_FILTER

chain=`iptables  -nL | grep CP_domain |awk '{print $2}'`
for x in $chain;do
        iptables -F $x
        iptables -X $x
done


iptables -t nat -D PREROUTING -j $CP_DNAT
iptables -t nat -F $CP_DNAT
iptables -t nat -X $CP_DNAT

chain=`iptables  -nL  -t nat |grep DNSS_DNAT_ |awk '{print $2}'`
for x in $chain;do
        iptables -t nat -F $x
        iptables -t nat -X $x
done

