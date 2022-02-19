#!/usr/bin/bash

#!/bin/bash

### Clear All
iptables -F
iptables -X
iptables -F -t nat
iptables -X -t nat
iptables -F -t filter
iptables -X -t filter

if [ "$1" = "stop" ]
then
        iptables -P INPUT ACCEPT
        iptables -P FORWARD ACCEPT
        iptables -P OUTPUT ACCEPT
        exit
fi

### Default policy
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT DROP

### LO
iptables -A INPUT -i lo -j ACCEPT

### Drop Ident
iptables -A INPUT -p tcp --dport 113 -j REJECT --reject-with icmp-port-unreachable 

### Security stuffs
#iptables -A INPUT -p tcp --syn -m limit --limit 3/s -j ACCEPT

#iptables -A INPUT -p udp -s 0/0 -f -j LOG --log-prefix "UDP Fragmentation "
#iptables -A INPUT -p udp -s 0/0 -j -j DROP

#iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s -j LOG --log-prefix "Ping: "
#iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s -j ACCEPT # Ping of death

iptables -A INPUT -m conntrack --ctstate NEW -p tcp --tcp-flags SYN,RST,ACK,FIN,URG,PSH ACK -j LOG --log-prefix "ACK scan: "
iptables -A INPUT -m conntrack --ctstate NEW -p tcp --tcp-flags SYN,RST,ACK,FIN,URG,PSH ACK -j DROP # Metoda ACK (nmap -sA)

iptables -A INPUT -m conntrack --ctstate NEW -p tcp --tcp-flags SYN,RST,ACK,FIN,URG,PSH FIN -j LOG --log-prefix "FIN scan: "
iptables -A INPUT -m conntrack --ctstate NEW -p tcp --tcp-flags SYN,RST,ACK,FIN,URG,PSH FIN -j DROP # Skanowanie FIN (nmap -sF)

iptables -A INPUT -m conntrack --ctstate NEW -p tcp --tcp-flags SYN,RST,ACK,FIN,URG,PSH PSH -j LOG --log-prefix "Xmas scan: "
iptables -A INPUT -m conntrack --ctstate NEW -p tcp --tcp-flags SYN,RST,ACK,FIN,URG,PSH FIN,URG,PSH -j DROP # Metoda Xmas Tree (nmap -sX)

iptables -A INPUT -m conntrack --ctstate INVALID -p tcp ! --tcp-flags SYN,RST,ACK,FIN,PSH,URG SYN,RST,ACK,FIN,PSH,URG -j LOG --log-prefix "Null scan: "
iptables -A INPUT -m conntrack --ctstate INVALID -p tcp ! --tcp-flags SYN,RST,ACK,FIN,PSH,URG SYN,RST,ACK,FIN,PSH,URG -j DROP # Skanowanie Null (nmap -sN)

### Against DoS
iptables -N syn-flood
iptables -A INPUT -p tcp --syn -j syn-flood
iptables -A syn-flood -m limit --limit 1/s --limit-burst 3 -j RETURN
iptables -A syn-flood -m limit --limit 1/s --limit-burst 3 -j LOG --log-prefix "SYN-flood: "
iptables -A syn-flood -j DROP

### Established
iptables -A INPUT -m conntrack --ctstate INVALID -j DROP
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

### SSH
iptables -t filter -I INPUT -p tcp --syn --dport 22 -m connlimit  --connlimit-above 5 --connlimit-mask 32 -j REJECT --reject-with tcp-reset 
#iptables -A INPUT -m conntrack --ctstate NEW -p tcp --dport 22 -j ACCEPT

### WWW
iptables -t filter -I INPUT -p tcp --syn --dport 80 -m connlimit  --connlimit-above 10 --connlimit-mask 32 -j DROP
iptables -t filter -I INPUT -p tcp --syn --dport 443 -m connlimit  --connlimit-above 10 --connlimit-mask 32 -j DROP
#iptables -A INPUT -m conntrack --ctstate NEW -p tcp --dport 80 -j ACCEPT
#iptables -A INPUT -m conntrack --ctstate NEW -p tcp --dport 443 -j ACCEPT

### DNS/Bind
iptables -A INPUT -m conntrack --ctstate NEW -p tcp --dport 53 -j ACCEPT
iptables -A INPUT -m conntrack --ctstate NEW -p udp --dport 53 -j ACCEPT

### FTP
iptables -A INPUT -m conntrack --ctstate NEW -p tcp --dport 20 -j ACCEPT
iptables -A INPUT -m conntrack --ctstate NEW -p tcp --dport 21 -j ACCEPT

##### OUTPUT:

iptables -A OUTPUT -m conntrack --ctstate INVALID -j LOG --log-prefix "DROP INVALID " --log-ip-options --log-tcp-options
iptables -A OUTPUT -m conntrack --ctstate INVALID -j DROP
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

iptables -A OUTPUT -m conntrack --ctstate NEW -p tcp --dport 20 -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate NEW -p tcp --dport 21 -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate NEW -p tcp --dport 80 -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate NEW -p tcp --dport 22 -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate NEW -p tcp --dport 443 -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate NEW -p tcp --dport 53 -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate NEW -p udp --dport 53 -j ACCEPT

# caĹ‚y ruch powyĹźej portĂłw 1024, to sÄ… porty ktĂłre mogÄ… byÄ‡ bindowane przez wszystko (chociaĹźby np. Kadu)
#iptables -A INPUT -m state --state NEW -p tcp --dport 1024:65535 -j ACCEPT
#iptables -A INPUT -m state --state NEW -p udp --dport 1024:65535 -j ACCEPT

# uruchomione serwery na portach poniĹźej 1024: ssh, http, https
#iptables -A INPUT -m state --state NEW -m multiport -p tcp --dports 22,80,443 -j ACCEPT

# Samba
#iptables -A INPUT -m state --state NEW -m multiport -p udp --dports 137,138 --source 192.168.1.0/24 -j ACCEPT
#iptables -A INPUT -m state --state NEW -m multiport -p tcp --dports 139,445 --source 192.168.1.0/24 -j ACCEPT

