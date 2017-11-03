#!/bin/bash
# CryptoStorm VPN Helper
# Developed by acidvegas
# https://github.com/acidvegas/vpntools
# cryptostorm.sh

DEFAULT_PROTOCOL=0 # 0 = udp | 1 = tcp
DEFAULT_SERVER=0
DISABLE_IPV6=1
ENABLE_KILLSWITCH=1

function disable_ipv6 {
	if [ ! -f /etc/sysctl.d/99-vpn-disable-ipv6.conf ]; then
		echo "net.ipv6.conf.all.disable_ipv6=1" > /etc/sysctl.d/99-vpn-disable-ipv6.conf
		echo "net.ipv6.conf.default.disable_ipv6=1" >> /etc/sysctl.d/99-vpn-disable-ipv6.conf
		echo "net.ipv6.conf.lo.disable_ipv6=1" >> /etc/sysctl.d/99-vpn-disable-ipv6.conf
		sysctl -w net.ipv6.conf.all.disable_ipv6=1
		sysctl -w net.ipv6.conf.default.disable_ipv6=1
		sysctl -w net.ipv6.conf.lo.disable_ipv6=1
	fi
}

function generate_config {
	if [ $DEFAULT_PROTOCOL -eq 0 ]; then
		PROTO='udp'
	elif [ $DEFAULT_PROTOCOL -eq 1 ]; then
		PROTO='tcp'
	else
		echo "[!] - Invalid protocol option!"
		exit 1
	esac
	>/etc/openvpn/client/cryptostorm/cryptostorm.conf
	if [ $1 == 'linux-cryptofree' ]; then
		echo "allow-pull-fqdn" >> /etc/openvpn/client/cryptostorm/cryptostorm.conf
	fi
	echo "auth SHA512" >> /etc/openvpn/client/cryptostorm/cryptostorm.conf
	echo "auth-user-pass auth" >> /etc/openvpn/client/cryptostorm/cryptostorm.conf
	echo "ca ca.crt" >> /etc/openvpn/client/cryptostorm/cryptostorm.conf
	echo "cipher AES-256-CBC" >> /etc/openvpn/client/cryptostorm/cryptostorm.conf
	echo "client" >> /etc/openvpn/client/cryptostorm/cryptostorm.conf
	echo "comp-lzo" >> /etc/openvpn/client/cryptostorm/cryptostorm.conf
	echo "dev tun0" >> /etc/openvpn/client/cryptostorm/cryptostorm.conf
	echo "down /etc/openvpn/scripts/update-systemd-resolved" >> /etc/openvpn/client/cryptostorm/cryptostorm.conf
	echo "down-pre" >> /etc/openvpn/client/cryptostorm/cryptostorm.conf
	if [ $PROTO == 'udp' ]; then
		echo "explicit-exit-notify" >> /etc/openvpn/client/cryptostorm/cryptostorm.conf
	fi
	if [ $1 == 'linux-cryptofree' ]; then
		echo "float" >> /etc/openvpn/client/cryptostorm/cryptostorm.conf
	fi
	echo "group vpn" >> /etc/openvpn/client/cryptostorm/cryptostorm.conf
	echo "hand-window 17" >> /etc/openvpn/client/cryptostorm/cryptostorm.conf
	echo "iproute /usr/local/sbin/unpriv-ip" >> /etc/openvpn/client/cryptostorm/cryptostorm.conf
	echo "key-method 2" >> /etc/openvpn/client/cryptostorm/cryptostorm.conf
	if [ $PROTO == 'udp' ]; then
		echo "mssfix 1400" >> /etc/openvpn/client/cryptostorm/cryptostorm.conf
	fi
	echo "mute 3" >> /etc/openvpn/client/cryptostorm/cryptostorm.conf
	echo "nobind" >> /etc/openvpn/client/cryptostorm/cryptostorm.conf
	echo "ns-cert-type server" >> /etc/openvpn/client/cryptostorm/cryptostorm.conf
	echo "persist-key" >> /etc/openvpn/client/cryptostorm/cryptostorm.conf
	echo "persist-tun" >> /etc/openvpn/client/cryptostorm/cryptostorm.conf
	echo "remote random" >> /etc/openvpn/client/cryptostorm/cryptostorm.conf
	echo "remote $1.cryptostorm.net 443 $PROTO" >> /etc/openvpn/client/cryptostorm/cryptostorm.conf
	echo "remote $1.cryptostorm.nu  443 $PROTO" >> /etc/openvpn/client/cryptostorm/cryptostorm.conf
	echo "remote $1.cryptostorm.org 443 $PROTO" >> /etc/openvpn/client/cryptostorm/cryptostorm.conf
	echo "remote $1.cryptostorm.pw  443 $PROTO" >> /etc/openvpn/client/cryptostorm/cryptostorm.conf
	echo "remote-cert-tls server" >> /etc/openvpn/client/cryptostorm/cryptostorm.conf
	echo "reneg-sec 0" >> /etc/openvpn/client/cryptostorm/cryptostorm.conf
	if [ $1 == 'linux-cryptofree' ]; then
		echo "replay-window 128 30" >> /etc/openvpn/client/cryptostorm/cryptostorm.conf
	fi
	echo "resolv-retry infinite" >> /etc/openvpn/client/cryptostorm/cryptostorm.conf
	echo "script-security 2" >> /etc/openvpn/client/cryptostorm/cryptostorm.conf
	echo "setenv PATH /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" >> /etc/openvpn/client/cryptostorm/cryptostorm.conf
	echo "tls-cipher TLS-DHE-RSA-WITH-AES-256-CBC-SHA" >> /etc/openvpn/client/cryptostorm/cryptostorm.conf
	echo "tls-client" >> /etc/openvpn/client/cryptostorm/cryptostorm.conf
	echo "tls-version-min 1.2" >> /etc/openvpn/client/cryptostorm/cryptostorm.conf
	if [ $1 == 'linux-cryptofree' ]; then
		echo "txqueuelen 686" >> /etc/openvpn/client/cryptostorm/cryptostorm.conf
	fi
	echo "up /etc/openvpn/scripts/update-systemd-resolved" >> /etc/openvpn/client/cryptostorm/cryptostorm.conf
	echo "user vpn" >> /etc/openvpn/client/cryptostorm/cryptostorm.conf
	echo "verb 4" >> /etc/openvpn/client/cryptostorm/cryptostorm.conf
}

# contributions by fermi @ cryptostorm
function killswitch {
	if [ -f /etc/iptables/vpn-rules.v4 ]; then
		iptables-restore < /etc/iptables/vpn.rules
	else
		iptables -F
		iptables -X
		iptables -Z
		iptables -t filter -F
		iptables -t filter -X
		iptables -t mangle -F
		iptables -t mangle -X
		iptables -t nat -F
		iptables -t nat -X
		iptables -t raw -F
		iptables -t raw -X
		iptables -t security -F
		iptables -t security -X
		iptables -P OUTPUT  DROP
		iptables -P INPUT   DROP
		iptables -P FORWARD DROP
		iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
		iptables -A INPUT -i lo -j ACCEPT
		iptables -A OUTPUT -o lo -j ACCEPT
		iptables -A INPUT -s 127.0.1.1 -j ACCEPT
		iptables -A OUTPUT -d 127.0.1.1 -j ACCEPT
		iptables -A INPUT -i tun+ -j ACCEPT
		iptables -A OUTPUT -p udp --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT
		iptables -A OUTPUT -p tcp --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT
		# option 1
		# starting with all internet traffic blocked, allows okturtles DNS in order
		# to resolve CS addresses against dnscrypt-cert.okturtles.com and create rules,
		# rule allowing okturtles DNS is removed after rules are created.
		nslookup public.deepdns.net 192.184.93.146 | awk '/Address: /{system ( "iptables -A OUTPUT -d " $2 " -p udp --dport 53 -j ACCEPT") }'
		nslookup linux-balancer.cstorm.pw 192.184.93.146 | awk '/Address: /{system ( "iptables -A OUTPUT -d " $2 " -p udp --dport 443 -j ACCEPT") }'
		nslookup linux.voodoo.network 192.184.93.146 | awk '/Address: /{system ( "iptables -A OUTPUT -d " $2 " -p udp --dport 443 -j ACCEPT") }'
		nslookup linux-cryptofree.cryptostorm.net 192.184.93.146 | awk '/Address: /{system ( "iptables -A OUTPUT -d " $2 " -p udp --dport 443 -j ACCEPT") }'
		# option 2:
		# DNS traffic is possible - CS addresses are resolved and rules are created
		# host cryptostorm-shared.deepdns.net | awk '{ system ( "iptables -A OUTPUT -d " $4 " -p udp --dport 53 -j ACCEPT") }'
		# host linux-balancer.cryptostorm.net | awk '{ system ( "iptables -A OUTPUT -d " $4 " -p udp --dport 443 -j ACCEPT") }'
		iptables -A OUTPUT -p -m --dport -j ACCEPT
		iptables -A OUTPUT -o tun+ -j ACCEPT
		iptables -A INPUT -s 192.168.1.0/24 -j ACCEPT
		iptables -A OUTPUT -d 192.168.1.0/24 -j ACCEPT
		iptables -A OUTPUT -j REJECT --reject-with icmp-net-unreachable
		iptables -A OUTPUT -p udp -m udp -m string --hex-string "|0001|" --algo bm --from 27 --to 28 -m string --hex-string "|2112a442|" --algo bm --from 30 --to 34 -j DROP
		iptables-save > /etc/iptables/vpn-rules.v4
	fi
	if [ $DISABLE_IPV6 -eq 1 ]; then
		if [ -f /etc/iptables/vpn-rules.v6 ]; then
			ip6tables-restore < /etc/iptables/vpn-rules.v6
		else
			ip6tables -F
			ip6tables -X
			ip6tables -Z
			ip6tables -t filter -F
			ip6tables -t filter -X
			ip6tables -t mangle -F
			ip6tables -t mangle -X
			ip6tables -t nat -F
			ip6tables -t nat -X
			ip6tables -t raw -F
			ip6tables -t raw -X
			ip6tables -t security -F
			ip6tables -t security -X
			ip6tables -P OUTPUT  DROP
			ip6tables -P INPUT   DROP
			ip6tables -P FORWARD DROP
			ip6tables-save > /etc/iptables/vpn-rules.v6
		fi
	fi
}

function menu_auth {
	USERNAME=$(dialog --backtitle "CryptoStorm VPN Helper" --title "Login" --inputbox "Username:" 8 50 2>&1 >/dev/tty)
	PASSWORD=$(dialog --backtitle "CryptoStorm VPN Helper" --title "Login" --clear --passwordbox "Password" 8 50 2>&1 >/dev/tty)
	clear
	echo -e "$USERNAME\n$PASSWORD" > /etc/openvpn/client/cryptostorm/auth
	chmod 600 /etc/openvpn/client/cryptostorm/auth
	chown root:root /etc/openvpn/client/cryptostorm/auth
}

function menu_server {
	if [ $DEFAULT_SERVER -eq 0 ]; then
		OPTIONS=(1 "Random"
			2  "Free"
			3  "Balancer"
			4  "Canada           (CA) - East"
			5  "Canada           (CA) - West"
			6  "Denmark          (DK)"
			7  "Germany          (DE) - Dusseldorf"
			8  "Germany          (DE) - Frankfurt"
			9  "Finland          (FI) - Paris"
			10 "France           (FR)"
			11 "Italy            (IT) - Rome"
			12 "Latvia           (LV)"
			13 "Lithuania        (LT)"
			14 "Moldova          (MD)"
			15 "Netherlands      (NL)"
			16 "Poland           (PL)"
			17 "Portugal         (PT) - Lisbon"
			18 "Romania          (RO) - Isle of Man (IM) (Voodoo)")
			19 "Romania          (RO) - Russia (RU)      (Voodoo)")
			20 "Spain            (ES)"
			21 "Switzerland	     (CH)"
			22 "United Kingdom   (GB) - England "
			23 "United States    (US) - East"
			24 "United States    (US) - North"
			25 "United States    (US) - South"
			26 "United States    (US) - West")
		CHOICE=$(dialog --clear --backtitle "CryptoStorm VPN Helper" --title "Connection" --menu "Select a regional server below:\n(The PF key indicates port forwarding can be enabled.)" 20 60 20 "${OPTIONS[@]}" 2>&1 >/dev/tty)
		clear
		if [ $CHOICE -eq 1 ]; then
			CHOICE=$(shuf -i 2-38 -n 1)
		fi
	elif [ $DEFAULT_SERVER == 1 ]; then
		CHOICE=$(shuf -i 2-38 -n 1)
	else
		CHOICE=$DEFAULT_SERVER
	fi
	case $CHOICE in
		2)  generate_config "linux-cryptofree";;
		3)  generate_config "linux-balancer";;
		4)  generate_config "linux-canadaeast";;
		5)  generate_config "linux-canadawest";;
		6)  generate_config "linux-denmark";;
		7)  generate_config "linux-dusseldorf";;
		8)  generate_config "linux-frankfurt";;
		9)  generate_config "linux-finland";;
		10) generate_config "linux-paris";;
		11) generate_config "linux-rome";;
		12) generate_config "linux-latvia";;
		13) generate_config "linux-lithuania";;
		14) generate_config "linux-moldova";;
		15) generate_config "linux-netherlands";;
		16) generate_config "linux-poland";;
		17) generate_config "linux-lisbon";;
		18) generate_config "voodoo-linux-isleofman";;
		19) generate_config "voodoo-linux-russia";;
		20) generate_config "linux-spain";;
		21) generate_config "linux-switzerland";;
		22) generate_config "linux-england";;
		23) generate_config "linux-useast";;
		24) generate_config "linux-usnorth";;
		25) generate_config "linux-ussouth";;
		26) generate_config "linux-uswest";;
	esac
}

function secure_dns {
	if [ ! -f /etc/openvpn/scripts/update-systemd-resolved ]; then
		mkdir -p /etc/openvpn/scripts
		wget -O /etc/openvpn/scripts/update-systemd-resolved https://raw.githubusercontent.com/jonathanio/update-systemd-resolved/master/update-systemd-resolved
		chmod 750 /etc/openvpn/scripts/update-systemd-resolved
	fi
	if [ -f /etc/nsswitch.conf ]; then
		if ! grep -q "hosts: files resolve myhostname" /etc/nsswitch.conf; then
			sed 's/hosts:.*/hosts: files resolve myhostname/' /etc/nsswitch.conf > /etc/nsswitch.conf
		fi
	else
		echo "[!] - Failed to locate /etc/nsswitch.conf file!"
		exit 1
	fi
	if ! $(/usr/bin/systemctl -q is-active systemd-resolved.service); then
		systemctl start systemd-resolved
	fi
	if ! $(/usr/bin/systemctl -q is-enabled systemd-resolved.service); then
		systemctl enable systemd-resolved
	fi
}

function setup {
	pacman -S dialog openvpn screen sudo
	mkdir -p /var/lib/openvpn
	if ! id vpn >/dev/null 2>&1; then
		useradd -r -d /var/lib/openvpn -s /usr/bin/nologin vpn
	fi
	if [ ! $(getent group vpn) ]; then
		groupadd vpn
	fi
	if ! getent group vpn | grep &>/dev/null "\bvpn\b"; then
		gpasswd -a vpn vpn
	fi
	chown vpn:vpn /var/lib/openvpn
	if [ -f /etc/sudoers ]; then
		if ! grep -q "vpn ALL=(ALL) NOPASSWD: /sbin/ip" /etc/sudoers; then
			echo -e "\nvpn ALL=(ALL) NOPASSWD: /sbin/ip" >> /etc/sudoers
		fi
		if ! grep -q "Defaults:vpn !requiretty" /etc/sudoers; then
			echo -e "\nDefaults:vpn !requiretty" >> /etc/sudoers
		fi
	else
		echo "[!] - Failed to locate /etc/sudoers file!"
		exit 1
	fi
	if [ ! -f /usr/local/sbin/unpriv-ip ]; then
		echo "#!/bin/sh" > /usr/local/sbin/unpriv-ip
		echo "sudo /sbin/ip \$*" >> /usr/local/sbin/unpriv-ip
		chmod 755 /usr/local/sbin/unpriv-ip
	fi
	if [ ! -f /etc/openvpn/openvpn-startup ]; then
		echo "#!/bin/sh" > /etc/openvpn/openvpn-startup
		echo "openvpn --rmtun --dev tun0" >> /etc/openvpn/openvpn-startup
		echo "openvpn --mktun --dev tun0 --dev-type tun --user vpn --group vpn" >> /etc/openvpn/openvpn-startup
		chmod 755 /etc/openvpn/openvpn-startup
	fi
	if [ -d /etc/openvpn/client/cryptostorm ]; then
		rm -r /etc/openvpn/client/cryptostorm
	fi
	mkdir /etc/openvpn/client/cryptostorm
	wget -O /etc/openvpn/client/cryptostorm/ca.crt https://raw.githubusercontent.com/cryptostorm/cryptostorm_client_configuration_files/master/ca.crt
	menu_auth
}

if [ $EUID -ne 0 ]; then
	echo "[!] - This script requires sudo privledges!"
	exit 1
fi
if [ ! -f /etc/openvpn/client/cryptostorm/auth ]; then
	setup
fi
secure_dns
if [ $DISABLE_IPV6 -eq 1 ]; then
	disable_ipv6
fi
menu_server
screen -S vpn -dm openvpn --cd /etc/openvpn/client/cryptostorm --config cryptostorm.conf #--daemon
if [ $ENABLE_KILLSWITCH -eq 1 ]; then
	killswitch
fi