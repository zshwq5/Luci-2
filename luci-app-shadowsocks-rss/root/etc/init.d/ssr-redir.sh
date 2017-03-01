#!/bin/sh /etc/rc.common
#
# Copyright (C) 2014 Justin Liu <rssnsj@gmail.com>
# https://github.com/rssnsj/network-feeds
#

START=99

#
# Data source of /etc/gfwlist/china-banned:
#  https://github.com/zhiyi7/ddwrt/blob/master/jffs/vpn/dnsmasq-gfw.txt
#  http://code.google.com/p/autoproxy-gfwlist/
#
NAME=shadowsocksr
SS_REDIR_PORT=7070
SS_TUNNEL_PORT=5300
SS_LOCAL_PORT=1090
PDNSD_LOCAL_PORT=7453
SSR_CONF=/etc/config/shadowsocksr
SSRCONF=/etc/shadowsocksr.json
CACHEDIR=/var/pdnsd
CACHE=$CACHEDIR/pdnsd.cache
USER=nobody
GROUP=nogroup

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-

# New implementation:
# Attach rules to main 'dnsmasq' service and restart it.

__gfwlist_by_mode()
{
	case "$1" in
		V) echo unblock-youku;;
		*) echo china-banned;;
	esac
}

uci_get_by_name() {
	local ret=$(uci get $NAME.$1.$2 2>/dev/null)
	#${}起到变量赋值作用,ret:=$3表示对未赋值的变量ret，把$3的值赋予它
	echo ${ret:=$3}
}

uci_get_by_type() {
	local ret=$(uci get $NAME.@$1[0].$2 2>/dev/null)
	#最终传给调用处得是echo的值
	echo ${ret:=$3}
}

uci_bool_by_name() {
	case "$(uci_get_by_name $1 $2)" in
		1|on|true|yes|enabled) return 0;;
	esac
	return 1
}
get_lan_hosts() {
	uci_bool_by_name $1 enable && \
		echo "$(uci_get_by_name $1 type),$(uci_get_by_name $1 host)"
}

gen_gfwlist_conf() {
	# $1=address $2=port $3=list
	awk -vs="$1#$2" '!/^$/&&!/^#/{printf("server=/%s/%s\n",$0,s)}' \
	/etc/gfwlist/$3 > /var/etc/dnsmasq-go.d/$3-pollution.conf
}

gen_ipset_conf() {
	# $1=list
	ipset -! create $1 hash:ip maxelem 65536 >/dev/null 2>&1
	awk '!/^$/&&!/^#/{printf("ipset=/%s/'"$1"'\n",$0)}' \
	/etc/gfwlist/$1 > /var/etc/dnsmasq-go.d/ipset-$1.conf
}

gen_lan_host_ipset() {
	#lan_hosts值为类似于b,192.168.1.223
	#${host:0:1}为首位字母，${host:2}为后面的ip
	ipset -! create SSR_AC_BYP hash:ip hashsize 64
	ipset -! create SSR_AC_NCN hash:ip hashsize 64
	ipset -! create SSR_AC_GFW hash:ip hashsize 64
	ipset -! create SSR_AC_ALL hash:ip hashsize 64
	ipset -! create SSR_AC_OVS hash:ip hashsize 64
	ipset -! create china-banned hash:ip hashsize 1024
	ipset -! create unblock-youku hash:ip hashsize 1024
	for host in $(config_foreach get_lan_hosts lan_hosts); do
		case "${host:0:1}" in
			B)
				ipset -! add SSR_AC_BYP ${host:2}
				;;
			S)
				ipset -! add SSR_AC_NCN ${host:2}
				;;
			M)
				gen_ipset_conf "china-banned"
				ipset -! add SSR_AC_GFW ${host:2}
				;;
			G)
				ipset -! add SSR_AC_ALL ${host:2}
				;;
			V)
				gen_ipset_conf "unblock-youku"
				ipset -! add SSR_AC_OVS ${host:2}
				;;
		esac
	done
}
get_global_target() {
	case "$1" in
		B)
			echo "RETURN"
		;;
		S)
			echo "SHADOWSOCKS_NCN"
		;;
		M)
			echo "SHADOWSOCKS_GFW"
		;;
		G)
			echo "SHADOWSOCKS_ALL"
		;;
		V)
			echo "SHADOWSOCKS_OVS"
		;;
	esac
}

ipt_redirect()
{
	if [ "$1" = "tcp" ];then
		echo "-p tcp -j REDIRECT --to $2"
	else
		echo "-p udp -j TPROXY --on-port $2 --tproxy-mark 0x01/0x01"
	fi
}

ipt_rules() {
	# $1=vt_dns_mode $2=proxy_mode $3=vt_server_addr $4=ssr-redir-port $5=subnet
	local protocol=$([ "$1" = "U" -o "$1" = "R" ] && echo udp || echo tcp)
	local table=$([ "$1" = "U" -o "$1" = "R" ] && echo mangle || echo nat)
	local file
	for file in /etc/ipset/*; do
		[ -f $file ] || continue
		ipset -! restore < $file
	done
	gen_lan_host_ipset
	if [ "$protocol" = "udp" ];then
		ip rule add fwmark 1 lookup 100
		ip route add local default dev lo table 100
	fi
	for i in SHADOWSOCKS SHADOWSOCKS_NCN SHADOWSOCKS_GFW SHADOWSOCKS_ALL SHADOWSOCKS_OVS;do
		iptables -t $table -N $i
		iptables -t $table -F $i
	done
	
	iptables -t $table -A SHADOWSOCKS -m set --match-set local dst -j RETURN
	iptables -t $table -A SHADOWSOCKS -d $3 -j RETURN
	iptables -t $table -A SHADOWSOCKS -m set --match-set SSR_AC_BYP src -j RETURN
	iptables -t $table -A SHADOWSOCKS -m set --match-set SSR_AC_NCN src -j SHADOWSOCKS_NCN
	iptables -t $table -A SHADOWSOCKS -m set --match-set SSR_AC_GFW src -j SHADOWSOCKS_GFW
	iptables -t $table -A SHADOWSOCKS -m set --match-set SSR_AC_ALL src -j SHADOWSOCKS_ALL
	iptables -t $table -A SHADOWSOCKS -m set --match-set SSR_AC_OVS src -j SHADOWSOCKS_OVS
	iptables -t $table -A SHADOWSOCKS -j $(get_global_target $2)
	# 非中国ip
	iptables -t $table -A SHADOWSOCKS_NCN -m set --match-set china dst -j RETURN
	iptables -t $table -A SHADOWSOCKS_NCN $(ipt_redirect $protocol $4)
	# gfwlist列表
	iptables -t $table -A SHADOWSOCKS_GFW -m set ! --match-set china-banned dst -j RETURN
	iptables -t $table -A SHADOWSOCKS_GFW -m set --match-set china dst -j RETURN
	iptables -t $table -A SHADOWSOCKS_GFW $(ipt_redirect $protocol $4)
	# 全局代理
	iptables -t $table -A SHADOWSOCKS_ALL $(ipt_redirect $protocol $4)
	# 海外看优酷
	iptables -t $table -A SHADOWSOCKS_OVS -m set ! --match-set unblock-youku dst -j RETURN
	iptables -t $table -A SHADOWSOCKS_OVS $(ipt_redirect $protocol $4)
	#应用规则
	iptables -t $table -I PREROUTING 1 -p $protocol -j SHADOWSOCKS

	if [ "$protocol" = "tcp" ];then
		#路由器自身访问openwrt,lede,github,raw.githubusercontent.com,通常用于更新gfwlist和源
		iptables -t $table -I OUTPUT -p $protocol -d 192.30.252.0/22 -j REDIRECT --to-port $4
		iptables -t $table -I OUTPUT -p $protocol -d 78.24.184.0/21 -j REDIRECT --to-port $4
		iptables -t $table -I OUTPUT -p $protocol -d 139.59.208.0/21 -j REDIRECT --to-port $4
		iptables -t $table -I OUTPUT -p $protocol -d 151.101.0.0/16 -j REDIRECT --to-port $4
		# 谷歌和opendns通过ssr-redir代理,这样能获得更精确结果.
		iptables -t $table -I OUTPUT -p $protocol -d 8.8.8.8,8.8.4.4 --dport 53 -j REDIRECT --to-ports $4
		iptables -t $table -I OUTPUT -p $protocol -d 208.67.222.222,208.67.220.220 -m multiport --dport 53,443,5353 -j REDIRECT --to-ports $4
	fi
}
flush_rules() {
	iptables-save -c | grep -v -i -E "china|SHADOWSOCKS|REDIRECT --to-ports $SS_REDIR_PORT" | iptables-restore -c
	if command -v ip >/dev/null 2>&1; then
		ip rule del fwmark 1 lookup 100 2>/dev/null
		ip route del local default dev lo table 100 2>/dev/null
	fi
	local setname
	for setname in $(ipset -n list | grep -i -E "china|local|unblock-youku|SSR_"); do
		ipset destroy $setname 2>/dev/null
	done
}

gen_ssr_conf(){
	cat > $SSRCONF <<-EOF
{
	"server": "$(config_get $1 server)",
	"server_port": "$(config_get $1 server_port)",
	"local_address": "0.0.0.0",
	"local_port": $SS_LOCAL_PORT,
	"password": "$(config_get $1 password)",
	"timeout": $(config_get $1 timeout),
	"method": "$(config_get $1 method)",
	"protocol": "$(config_get $1 protocol)",
	"obfs": "$(config_get $1 obfs)",
	"obfs_param": "$(config_get $1 obfs_param)"
}
EOF
}

# $1: upstream DNS server
start_pdnsd()
{
	#safe_dns="$2" safe_dns_port="$3" $1=vt_dns_mode
	local vt_pcap_pid=`pidof Pcap_DNSProxy 2>/dev/null`
	local vt_pcap_listen_port=`awk '/^Listen Port/{print $4}' /etc/pcap-dnsproxy/Config.conf 2>/dev/null`
	local tcp_dns_list="208.67.222.222, 208.67.220.220"
	[ "$3" -eq 5353 ] && tcp_dns_list="$2,$tcp_dns_list"
	[ "$1" = "R" ] && local query_method=udp_tcp || local query_method=tcp_only
	stop_pdnsd && sleep 1
	if ! test -f "$CACHE"; then
		mkdir -p $CACHEDIR
		dd if=/dev/zero of="$CACHE" bs=1 count=4 2> /dev/null
		chown -R $USER.$GROUP $CACHEDIR
	fi
	mkdir -p /var/etc
	cat > /var/etc/pdnsd.conf <<EOF
global {
	perm_cache=10240;
	cache_dir="/var/pdnsd";
	pid_file = /var/run/pdnsd.pid;
	run_as="nobody";
	server_ip = 127.0.0.1;
	server_port = $PDNSD_LOCAL_PORT;
	status_ctl = on;
	query_method = $query_method;
	min_ttl=1d;
	max_ttl=1w;
	timeout=10;
	neg_domain_pol=on;
	proc_limit=2;
	procq_limit=8;
}
EOF
	case "$1" in
		D) : ;;
		F|R)
			cat >> /var/etc/pdnsd.conf <<EOF
server {
	label= "local";
	ip = $2;
	port = $3;
	timeout=6;
	uptest=none;
	interval=10m;
	purge_cache=off;
}
EOF
			;;
	esac
	cat >> /var/etc/pdnsd.conf <<EOF
server {
	label= "fuckgfw";
	ip = $tcp_dns_list;
	port = 5353;
	timeout=6;
	uptest=none;
	interval=10m;
	purge_cache=off;
}
EOF
	if [ "$2" != "127.0.0.1" -a "$3" -ne "5353" ]; then
	cat >> /var/etc/pdnsd.conf <<EOF
server {
	label= "Custom";
	ip = $2;
	port = $3;
	timeout=6;
	uptest=none;
	interval=10m;
	purge_cache=off;
}
EOF
	fi
	/usr/sbin/pdnsd -c /var/etc/pdnsd.conf -d
}

stop_pdnsd()
{
	killall -9 pdnsd 2>/dev/null
	rm -rf /var/pdnsd
	rm -f /var/etc/pdnsd.conf
}

start_pcap()
{
	stop_pcap
	sed -i '/^\[DNS\]/{n;s/IPv4 + UDP/...TCP/;}' /etc/pcap-dnsproxy/Config.conf
	case "$1" in
		Q)
			sed -i '/^SOCKS Proxy =/ c\SOCKS Proxy = 1' /etc/pcap-dnsproxy/Config.conf
			sed -i "/^SOCKS IPv4 Address/ c\SOCKS IPv4 Address = 127.0.0.1:$SS_LOCAL_PORT" /etc/pcap-dnsproxy/Config.conf
			;;
		*)
			sed -i '/^SOCKS Proxy =/ c\SOCKS Proxy = 0' /etc/pcap-dnsproxy/Config.conf
			;;
	esac	
	uci set pcap-dnsproxy.@pcap-dnsproxy[0].enabled=1
	uci commit pcap-dnsproxy
	/etc/init.d/pcap-dnsproxy start	2>/dev/null
}
stop_pcap()
{
	uci set pcap-dnsproxy.@pcap-dnsproxy[0].enabled=0
	uci commit pcap-dnsproxy
	/etc/init.d/pcap-dnsproxy stop 2>/dev/null
}

start()
{
	config_load $SSR_CONF
	local vt_enabled=$(uci_get_by_type global enabled)
	local vt_safe_dns=$(uci_get_by_type upstream_dns safe_dns)
	local vt_safe_dns_port=$(uci_get_by_type upstream_dns safe_dns_port)
	local vt_dns_mode=$(uci_get_by_type global dns_mode)
	local vt_proxy_mode=$(uci_get_by_type global proxy_mode)
	local global_server=$(uci_get_by_type global global_server)
	local pdnsd_pid=`pidof pdnsd 2>/dev/null`
	local pcap_pid=`pidof Pcap_DNSProxy 2>/dev/null`
	local pcap_listen_port=`awk '/^Listen Port/{print $4}' /etc/pcap-dnsproxy/Config.conf 2>/dev/null`
	[ -n "$pdnsd_pid" ] && stop_pdnsd
	[ -n "$pcap_pid" ] && stop_pcap

	# -----------------------------------------------------------------
	if [ "$vt_enabled" = 0 ]; then
		echo "WARNING: Shadowsocksr is disabled."
		return 1
	fi
	[ -z "$vt_proxy_mode" ] && vt_proxy_mode=M
	[ -z "$vt_method" ] && vt_method=table
	[ -z "$vt_timeout" ] && vt_timeout=60
	case "$vt_proxy_mode" in
		M|S|G)
			[ -z "$vt_safe_dns" ] && vt_safe_dns="8.8.8.8"
			;;
	esac
	[ -z "$vt_safe_dns_port" ] && vt_safe_dns_port=53
	# Get LAN settings as default parameters
	[ -f /lib/functions/network.sh ] && . /lib/functions/network.sh
	[ -z "$covered_subnets" ] && network_get_subnet covered_subnets lan
	[ -z "$local_addresses" ] && network_get_ipaddr local_addresses lan
	vt_gfwlist=`__gfwlist_by_mode $vt_proxy_mode`
	vt_np_ipset="china"  # Must be global variable

	# -----------------------------------------------------------------
	###### shadowsocksr ######
	gen_ssr_conf $global_server

	# -----------------------------------------------------------------
	mkdir -p /var/etc/dnsmasq-go.d
	###### Anti-pollution configuration ######
	if [ -n "$vt_safe_dns" -a "$vt_safe_dns" != "127.0.0.1" ]; then
		case "$vt_dns_mode" in
		D)
			start_pdnsd "$vt_dns_mode" "$vt_safe_dns" "$vt_safe_dns_port"
			gen_gfwlist_conf "127.0.0.1" "$PDNSD_LOCAL_PORT" "$vt_gfwlist"
			;;
		R)
			start_pdnsd "$vt_dns_mode" "127.0.0.1" "$SS_TUNNEL_PORT"
			gen_gfwlist_conf "127.0.0.1" "$PDNSD_LOCAL_PORT" "$vt_gfwlist"
			;;		
		P|Q)
			start_pcap "$vt_dns_mode"
			gen_gfwlist_conf "127.0.0.1" "$pcap_listen_port" "$vt_gfwlist"
			;;
		F)
			start_pcap "$vt_dns_mode"
			start_pdnsd "$vt_dns_mode" "127.0.0.1" "$pcap_listen_port"
			gen_gfwlist_conf "127.0.0.1" "$PDNSD_LOCAL_PORT" "$vt_gfwlist"
			;;
		U)
			gen_gfwlist_conf "127.0.0.1" "$SS_TUNNEL_PORT" "$vt_gfwlist"
			;;
		esac
	elif [ -n "$vt_safe_dns" -a "$vt_safe_dns" = "127.0.0.1" ]; then
			gen_gfwlist_conf "$vt_safe_dns" "$vt_safe_dns_port" "$vt_gfwlist"
	else
		echo "WARNING: Not using secure DNS, DNS resolution might be polluted if you are in China."
	fi

	###### dnsmasq-to-ipset configuration ######
	case "$vt_proxy_mode" in
		M|V)
			gen_ipset_conf "$vt_gfwlist"
			;;
	esac
	#------------------------------------------------------------------------------
	# run ssr and add ipv4 firewall_fules
	case "$vt_dns_mode" in
		Q)
			ipt_rules "$vt_dns_mode" "$vt_proxy_mode" "$(config_get $global_server server)" "$SS_REDIR_PORT" "$covered_subnets"
			/usr/bin/ssr-redir -c $SSRCONF -l $SS_REDIR_PORT -f /var/run/ssr-redir.pid
			/usr/bin/ssr-local -c $SSRCONF -l $SS_LOCAL_PORT -f /var/run/ssr-local.pid -u
			;;
		U|R)
			ipt_rules "TCP" "$vt_proxy_mode" "$(config_get $global_server server)" "$SS_REDIR_PORT" "$covered_subnets"
			ipt_rules "$vt_dns_mode" "$vt_proxy_mode" "$(config_get $global_server server)" "$SS_REDIR_PORT" "$covered_subnets"
			/usr/bin/ssr-redir -c $SSRCONF -l $SS_REDIR_PORT -f /var/run/ssr-redir.pid
			/usr/bin/ssr-redir -c $SSRCONF -l $SS_REDIR_PORT \
				-f /var/run/ssr-redir-udp.pid -U
			/usr/bin/ssr-tunnel -c $SSRCONF -l $SS_TUNNEL_PORT \
				-f /var/run/ssr-tunnel.pid \
				-L $vt_safe_dns:$vt_safe_dns_port -U
			;;
		*)
			ipt_rules "$vt_dns_mode" "$vt_proxy_mode" "$(config_get $global_server server)" "$SS_REDIR_PORT" "$covered_subnets"
			/usr/bin/ssr-redir -c $SSRCONF -l $SS_REDIR_PORT -f /var/run/ssr-redir.pid
			;;
	esac
	
	# -----------------------------------------------------------------
	###### Restart main 'dnsmasq' service if needed ######
	if ls /var/etc/dnsmasq-go.d/* >/dev/null 2>&1; then
		mkdir -p /tmp/dnsmasq.d
		cat > /tmp/dnsmasq.d/dnsmasq-go.conf <<-EOF
		conf-dir=/var/etc/dnsmasq-go.d
		EOF
		/etc/init.d/dnsmasq restart

		# Check if DNS service was really started
		local dnsmasq_ok=N
		local i
		for i in 0 1 2 3 4 5 6 7; do
			sleep 1
			local dnsmasq_pid=`pidof dnsmasq 2>/dev/null`
			if [ -n "$dnsmasq_pid" ]; then
				if kill -0 "$dnsmasq_pid" 2>/dev/null; then
					dnsmasq_ok=Y
					break
				fi
			fi
		done
		if [ "$dnsmasq_ok" != Y ]; then
			echo "WARNING: Attached dnsmasq rules will cause the service startup failure. Removed those configurations."
			rm -f /tmp/dnsmasq.d/dnsmasq-go.conf
			/etc/init.d/dnsmasq restart
		fi
	fi

}

stop()
{
	local pdnsd_pid=`pidof pdnsd 2>/dev/null`
	local pcap_pid=`pidof Pcap_DNSProxy 2>/dev/null`

	# -----------------------------------------------------------------
	rm -rf /var/etc/dnsmasq-go.d
	if [ -f /tmp/dnsmasq.d/dnsmasq-go.conf ]; then
		rm -f /tmp/dnsmasq.d/dnsmasq-go.conf
		/etc/init.d/dnsmasq restart
	fi
	
	[ -n "$pdnsd_pid" ] && stop_pdnsd
	[ -n "$pcap_pid" ] && stop_pcap
	# -----------------------------------------------------------------
	# clear added firewall and ipset rules
	flush_rules
	#stop ssr
	local pidfile
	for pidfile in /var/run/ssr-*.pid; do
		kill -9 `cat $pidfile 2>/dev/null`
		rm -f $pidfile >/dev/null 2>&1
	done
}

restart()
{
	KEEP_GFWLIST=Y
	stop
	start
}