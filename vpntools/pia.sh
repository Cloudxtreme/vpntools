#!/bin/bash
# PIA VPN Helper
# Developed by acidvegas
# https://github.com/acidvegas/vpntools
# pia.sh

DEFAULT_SCHEME=0
DEFAULT_SERVER=0
DISABLE_IPV6=1
ENABLE_KILLSWITCH=1
ENABLE_PORT_FORWARD=0

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
	if [ $DEFAULT_SCHEME == 0 ]; then
		OPTIONS=(1  "53   | UDP | BF-CBC      | SHA1"
			2  "80   | TCP | BF-CBC      | SHA1"
			3  "110  | TCP | BF-CBC      | SHA1"
			4  "443  | TCP | BF-CBC      | SHA1"
			5  "501  | TCP | AES-256-CBC | SHA256"
			6  "502  | TCP | AES-128-CBC | SHA1"
			7  "1194 | UDP | BF-CBC      | SHA1"
			8  "1197 | UDP | AES-256-CBC | SHA256"
			9  "1198 | UDP | AES-128-CBC | SHA1"
			10 "8080 | UDP | BF-CBC      | SHA1"
			11 "9201 | UDP | BF-CBC      | SHA1")
		CHOICE=$(dialog --clear --backtitle "PIA VPN Helper" --title "Connection" --menu "Select a connection scheme:\n(Port   Protocol   Encryption Cipher   Auth Hash)" 20 60 20 "${OPTIONS[@]}" 2>&1 >/dev/tty)
		clear
	else
		CHOICE=$DEFAULT_SCHEME
	fi
	case $CHOICE in
		1)  PORT="53";   PROTO="udp"; CIPHER="bf-cbc";      AUTH="sha1";   CA="ca.crt";          CRL="crl.pem";;
		2)  PORT="80";   PROTO="tcp"; CIPHER="bf-cbc";      AUTH="sha1";   CA="ca.crt";          CRL="crl.pem";;
		3)  PORT="110";  PROTO="tcp"; CIPHER="bf-cbc";      AUTH="sha1";   CA="ca.crt";          CRL="crl.pem";;
		4)  PORT="443";  PROTO="tcp"; CIPHER="bf-cbc";      AUTH="sha1";   CA="ca.crt";          CRL="crl.pem";;
		5)  PORT="501";  PROTO="tcp"; CIPHER="aes-256-cbc"; AUTH="sha256"; CA="ca.rsa.4096.crt"; CRL="crl.rsa.4096.pem";;
		6)  PORT="502";  PROTO="tcp"; CIPHER="aes-128-cbc"; AUTH="sha1";   CA="ca.rsa.2048.crt"; CRL="crl.rsa.2048.pem";;
		7)  PORT="1194"; PROTO="udp"; CIPHER="bf-cbc";      AUTH="sha1";   CA="ca.crt";          CRL="crl.pem";;
		8)  PORT="1197"; PROTO="udp"; CIPHER="aes-256-cbc"; AUTH="sha256"; CA="ca.rsa.4096.crt"; CRL="crl.rsa.4096.pem";;
		9)  PORT="1198"; PROTO="udp"; CIPHER="aes-128-cbc"; AUTH="sha1";   CA="ca.rsa.2048.crt"; CRL="crl.rsa.2048.pem";;
		10) PORT="8080"; PROTO="udp"; CIPHER="bf-cbc";      AUTH="sha1";   CA="ca.crt";          CRL="crl.pem";;
		11) PORT="9201"; PROTO="udp"; CIPHER="bf-cbc";      AUTH="sha1";   CA="ca.crt";          CRL="crl.pem";;
	esac
	echo "auth $AUTH
auth-user-pass auth
ca $CA
cipher $CIPHER
client
comp-lzo
crl-verify $CRL
dev tun0
down /etc/openvpn/scripts/update-systemd-resolved
down-pre
group vpn
iproute /usr/local/sbin/unpriv-ip
mute 3
nobind
persist-key
persist-tun
proto $PROTO
remote $1.privateinternetaccess.com $PORT
remote-cert-tls server
reneg-sec 0
resolv-retry infinite
script-security 2
setenv PATH /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
tls-client
tls-version-min 1.2
up /etc/openvpn/scripts/update-systemd-resolved
user vpn
verb 4" > /etc/openvpn/client/pia/pia.conf
}

function killswitch {
	if [ -f /etc/iptables/vpn-rules.v4 ]; then
		iptables-restore < /etc/iptables/vpn-rules.v4
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
		iptables -A INPUT -i tun+ -j ACCEPT
		iptables -A OUTPUT -o lo -j ACCEPT
		iptables -A OUTPUT -d 209.222.18.222/32 -j ACCEPT
		iptables -A OUTPUT -d 209.222.18.218/32 -j ACCEPT
		iptables -A OUTPUT -p  -m  --dport  -j ACCEPT
		iptables -A OUTPUT -o tun+ -j ACCEPT
		iptables -A INPUT -s 192.168.1.0/24 -j ACCEPT
		iptables -A OUTPUT -d 192.168.1.0/24 -j ACCEPT
		iptables -A OUTPUT -j REJECT --reject-with icmp-net-unreachable
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
	USERNAME=$(dialog --backtitle "PIA VPN Helper" --title "Login" --inputbox "Username:" 8 50 2>&1 >/dev/tty)
	PASSWORD=$(dialog --backtitle "PIA VPN Helper" --title "Login" --clear --passwordbox "Password" 8 50 2>&1 >/dev/tty)
	clear
	echo -e "$USERNAME\n$PASSWORD" > /etc/openvpn/client/pia/auth
	chmod 600 /etc/openvpn/client/pia/auth
	chown root:root /etc/openvpn/client/pia/auth
}

function menu_server {
	if [ $DEFAULT_SERVER -eq 0 ]; then
		OPTIONS=(1 "Random"
			2  "Australia      (AU)"
			3  "Australia      (AU) - Melbourne"
			4  "Brazil         (BR)"
			5  "Canada         (CA)                  (PF)"
			6  "Canada         (CA) - Toronto        (PF)"
			7  "Denmark        (DK)"
			8  "Finland        (FI)"
			9  "France         (FR)                  (PF)"
			10 "Germany        (DE)                  (PF)"
			11 "Hong Kong      (HK)"
			12 "India          (IN)"
			13 "Ireland        (IE)"
			14 "Israel         (IL)                  (PF)"
			15 "Italy          (IT)"
			16 "Japan          (JP)"
			17 "South Korea	   (KR)"
			18 "Mexico         (MX)"
			19 "Netherlands    (NL)                  (PF)"
			20 "Norway         (NO)"
			21 "New Zealand	   (NZ)"
			22 "Romania        (RO)                  (PF)"
			23 "Singapore      (SG)"
			24 "Sweden         (SE)                  (PF)"
			25 "Switzerland	   (CH)                  (PF)"
			26 "Turkey         (TR)"
			27 "United Kingdom (GB) - London"
			28 "United Kingdom (GB) - Southampton"
			29 "United States  (US) - California"
			30 "United States  (US) - Chicago"
			31 "United States  (US) - East"
			32 "United States  (US) - Florida"
			33 "United States  (US) - Midwest"
			34 "United States  (US) - NYC"
			35 "United States  (US) - Seattle"
			36 "United States  (US) - Silicon Valley"
			37 "United States  (US) - Texas"
			38 "United States  (US) - West")
		CHOICE=$(dialog --clear --backtitle "PIA VPN Helper" --title "Connection" --menu "Select a regional server below:\n(The PF key indicates port forwarding can be enabled.)" 20 60 20 "${OPTIONS[@]}" 2>&1 >/dev/tty)
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
		2)  generate_config "aus";;
		3)  generate_config "aus-melbourne";;
		4)  generate_config "brazil";;
		5)  generate_config "ca";;
		6)  generate_config "ca-toronto";;
		7)  generate_config "denmark";;
		8)  generate_config "fi";;
		9)  generate_config "france";;
		10) generate_config "germany";;
		11) generate_config "hk";;
		12) generate_config "in";;
		13) generate_config "ireland";;
		14) generate_config "israel";;
		15) generate_config "italy";;
		16) generate_config "japan";;
		17) generate_config "kr";;
		18) generate_config "mexico";;
		19) generate_config "nl";;
		20) generate_config "no";;
		21) generate_config "nz";;
		22) generate_config "ro";;
		23) generate_config "sg";;
		24) generate_config "sweden";;
		25) generate_config "swiss";;
		26) generate_config "turkey";;
		27) generate_config "uk-london";;
		28) generate_config "uk-southhampton";;
		29) generate_config "us-california";;
		30) generate_config "us-chicago";;
		31) generate_config "us-east";;
		32) generate_config "us-florida";;
		33) generate_config "us-west";;
		34) generate_config "us-newyorkcity";;
		35) generate_config "us-seattle";;
		36) generate_config "us-siliconvalley";;
		37) generate_config "us-texas";;
		38) generate_config "us-west";;
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
	if [ -d /etc/openvpn/client/pia ]; then
		rm -r /etc/openvpn/client/pia
	fi
	mkdir /etc/openvpn/client/pia
	wget -O /etc/openvpn/client/pia/ca.rsa.2048.crt http://www.privateinternetaccess.com/openvpn/ca.rsa.2048.crt
	wget -O /etc/openvpn/client/pia/crl.rsa.2048.pem http://www.privateinternetaccess.com/openvpn/crl.rsa.2048.pem
	wget -O /etc/openvpn/client/pia/ca.rsa.4096.crt http://www.privateinternetaccess.com/openvpn/ca.rsa.4096.crt
	wget -O /etc/openvpn/client/pia/crl.rsa.4096.pem http://www.privateinternetaccess.com/openvpn/crl.rsa.4096.pem
	wget -O /etc/openvpn/client/pia/ca.crt http://www.privateinternetaccess.com/openvpn/ca.crt
	wget -O /etc/openvpn/client/pia/crl.pem http://www.privateinternetaccess.com/openvpn/crl.pem
	menu_auth
}

function port_forward {
	CLIENT_ID=`head -n 100 /dev/urandom | sha256sum | tr -d " -"`
	JSON=$(curl -s -f "http://209.222.18.222:2000/?client_id=$client_id")
	if [ -z $JSON ]; then
		echo "[!] - Port forwarding is already activated on this connection, has expired, or you are not connected to a PIA region that supports port forwarding."
		echo "[!] - Supported regions include Canada (Toronto), France, Germany, Israel, Netherlands, Romania, Sweden, & Switzerland"
		exit 1
	else
		OPEN_PORT=$(echo $pia_response | grep -oE "[0-9]+")
		echo "[+] - Port forward has been enabled on port $OPEN_PORT"
	fi
}

if [ $EUID -ne 0 ]; then
	echo "[!] - This script requires sudo privledges!"
	exit 1
fi
if [ ! -f /etc/openvpn/client/pia/auth ]; then
	setup
fi
secure_dns
if [ $DISABLE_IPV6 -eq 1 ]; then
	disable_ipv6
fi
menu_server
screen -S vpn -dm openvpn --cd /etc/openvpn/client/pia --config pia.conf #--daemon
if [ $ENABLE_KILLSWITCH -eq 1 ]; then
	killswitch
fi
if [ $ENABLE_PORT_FORWARD -eq 1 ]; then
	port_forward
fi