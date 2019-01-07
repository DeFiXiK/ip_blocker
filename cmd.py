TCPDUMP = "tcpdump -i {iface} -n -x src not {hostname}"

IPTABLES_CLEAR = "iptables -F"
IPTABLES_ADD_BLOCK_RULE = "iptables -A INPUT -m state --state NEW -m set --match-set badip src -j DROP"

IPSET_CHECK = "ipset test badip {ip}"
IPSET_ADD = "ipset add badip {ip}"
