#### Firewall KVM Host - Centofon ####
 
Iptables for KVM host:
 
  
#!/usr/bin/bash
 
  
###
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
 
  
###
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT
 
# peĹ‚ny ruch na interfejsie lo (potrzebne do dziaĹ‚ania wielu lokalnych usĹ‚ug)
iptables -A INPUT -i lo -j ACCEPT
 
# odrzucamy ident
iptables -A INPUT -p tcp --dport 113 -j REJECT --reject-with icmp-port-unreachable  
 
# ochrona przed atakami
iptables -A INPUT -p tcp --syn -m limit --limit 3/s -j ACCEPT
 
####  
#iptables -A INPUT -p udp -s 0/0 -f -j LOG --log-prefix "UDP Fragmentation "
#iptables -A INPUT -p udp -s 0/0 -j -j DROP
 
iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s -j LOG --log-prefix "Ping: "
iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s -j ACCEPT # Ping of death
 
iptables -A INPUT -m conntrack --ctstate NEW -p tcp --tcp-flags SYN,RST,ACK,FIN,URG,PSH ACK -j LOG --log-prefix "ACK scan: "
iptables -A INPUT -m conntrack --ctstate NEW -p tcp --tcp-flags SYN,RST,ACK,FIN,URG,PSH ACK -j DROP # Metoda ACK (nmap -sA)
 
iptables -A INPUT -m conntrack --ctstate NEW -p tcp --tcp-flags SYN,RST,ACK,FIN,URG,PSH FIN -j LOG --log-prefix "FIN scan: "
iptables -A INPUT -m conntrack --ctstate NEW -p tcp --tcp-flags SYN,RST,ACK,FIN,URG,PSH FIN -j DROP # Skanowanie FIN (nmap -sF)
 
iptables -A INPUT -m conntrack --ctstate NEW -p tcp --tcp-flags SYN,RST,ACK,FIN,URG,PSH PSH -j LOG --log-prefix "Xmas scan: "
iptables -A INPUT -m conntrack --ctstate NEW -p tcp --tcp-flags SYN,RST,ACK,FIN,URG,PSH FIN,URG,PSH -j DROP # Metoda Xmas Tree (nmap -sX)
 
iptables -A INPUT -m conntrack --ctstate INVALID -p tcp ! --tcp-flags SYN,RST,ACK,FIN,PSH,URG SYN,RST,ACK,FIN,PSH,URG -j LOG --log-prefix "Null scan: "
iptables -A INPUT -m conntrack --ctstate INVALID -p tcp ! --tcp-flags SYN,RST,ACK,FIN,PSH,URG SYN,RST,ACK,FIN,PSH,URG -j DROP # Skanowanie Null (nmap -sN)
 
# Ĺ aĹ„cuch syn-flood (obrona przed DoS)
iptables -N syn-flood
iptables -A INPUT -p tcp --syn -j syn-flood
iptables -A syn-flood -m limit --limit 1/s --limit-burst 4 -j RETURN
iptables -A syn-flood -m limit --limit 1/s --limit-burst 4 -j LOG --log-prefix "SYN-flood: "
iptables -A syn-flood -j DROP
 
# pozwalamy na wszystkie istniejÄ…ce juĹź poĹ‚Ä…czenia oraz poĹ‚Ä…czenia ktĂłre sÄ… powiÄ…zane z istniejÄ…cymi juĹź poĹ‚Ä…czeniami
iptables -A INPUT -m conntrack --ctstate INVALID -j DROP
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
 
### ssh:
iptables -A INPUT -m conntrack --ctstate NEW -p tcp --dport 22 -j ACCEPT
iptables -t filter -I INPUT -p tcp --syn --dport 22 -m connlimit  --connlimit-above 5 --connlimit-mask 32 -j REJECT --reject-with tcp-reset
 
### vnc:
iptables -A INPUT -m conntrack --ctstate NEW -p tcp --dport 7000 -j ACCEPT
#iptables -A INPUT -m conntrack --ctstate NEW -p tcp --dport 7001 -j ACCEPT
