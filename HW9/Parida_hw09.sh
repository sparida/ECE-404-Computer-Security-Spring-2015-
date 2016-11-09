#!/usr/bin/env bash

#HW #: HW 9(iptables) (ECE 404 Spring 2015)
#Name: Sthitapragyan Parida
#ECN Login: sparida
#Due Date: 4/2/2015

# ath0 is internal interface 
# eth0 is extrenal interface

# Clear out all tables and delete all chains
iptables -t filter -F
iptables -t filter -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X
iptables -t raw -F
iptables -t raw -X


#1 
# Accepts all outgoing packets
iptables -P OUTPUT ACCEPT

#2
# IP Addresses to be blocked
iplist=(10.10.10.10 11.11.11.11 12.12.12.12)
for ipl in ${iplist[*]};
do
iptables -A INPUT -s $ipl -j DROP
done

#3
# Prevent users from being able to ping
iptables -A INPUT -p icmp --icmp-type echo-request -j DROP

#4
# Forward packets from 22223 to 22(SSH)
iptables -A INPUT -p tcp -m tcp --dport 22223 -j ACCEPT
iptables -A FORWARD -p tcp -m tcp --dport 22223 -j ACCEPT
iptables -t nat -A PREROUTING -i ath0 -p tcp --dport 2222 -j REDIRECT --to-port 22
iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 2222 -j REDIRECT --to-port 22

#5
# First ip allows ssh access to all servers in ecn domain while the second one covers jarvis
iptables -A INPUT -i eth0 -p tcp -s 128.46.4.0/24 --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT -i eth0 -p tcp -s 172.31.6.2 --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT

#6
hip="128.128.128.128" # ipadress to accept http connection from 
iptables -A INPUT -p tcp --dport 8000 -s $hip -j ACCEPT

#7
# Permit Auth/Ident(113) used by SMTP and IRC amongst others
iptables -A INPUT -m state --state=NEW,ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -i eth0 -p tcp --dport 113 --syn -j ACCEPT

# Drop every other connection and accept all packets generated locally
iptables -A FORWARD -i ath0 -j ACCEPT
iptables -A FORWARD -j REJECT --reject-with icmp-host-prohibited

iptables -A INPUT -i ath0 -j ACCEPT
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -j REJECT --reject-with icmp-host-prohibited

