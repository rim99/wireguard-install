#!/bin/bash
#
# https://github.com/hwdsl2/wireguard-install
#
# Based on the work of Nyr and contributors at:
# https://github.com/Nyr/wireguard-install
#
# Copyright (c) 2022-2023 Lin Song <linsongui@gmail.com>
# Copyright (c) 2020-2023 Nyr
#
# Released under the MIT License, see the accompanying file LICENSE.txt
# or https://opensource.org/licenses/MIT

exiterr()  { echo "Error: $1" >&2; exit 1; }
exiterr2() { exiterr "'apk add' failed."; }

firewall="nftables"
wgfw="wg-firewall"

check_ip() {
	IP_REGEX='^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$'
	printf '%s' "$1" | tr -d '\n' | grep -Eq "$IP_REGEX"
}


install_iproute() {
	if ! hash ip 2>/dev/null; then
		if [ "$auto" = 0 ]; then
			echo "iproute is required to use this installer."
			read -n1 -r -p "Press any key to install iproute and continue..."
		fi
		(
			set -x
			apk add iproute2 >/dev/null
		) || exiterr2
	fi
}

install_wg_tool() {
	if ! hash wg 2>/dev/null; then
		if [ "$auto" = 0 ]; then
			echo "wireguard-tools is required to use this installer."
			read -n1 -r -p "Press any key to install wireguard-tools and continue..."
		fi
		(
			set -x
			apk add wireguard-tools >/dev/null
		) || exiterr2
	fi
}

install_nftables() {
	if ! hash nft 2>/dev/null; then
		if [ "$auto" = 0 ]; then
			echo "nftables is required to use this installer."
			read -n1 -r -p "Press any key to install nftables and continue..."
		fi
		(
			set -x
			apk add nftables >/dev/null
		) || exiterr2
	fi
}

show_start_setup() {
	if [ "$auto" = 0 ]; then
		echo
		echo 'Welcome to this WireGuard server installer!'
		echo 'GitHub: https://github.com/hwdsl2/wireguard-install'
		echo
		echo 'I need to ask you a few questions before starting setup.'
		echo 'You can use the default options and just press enter if you are OK with them.'
	else
		show_header
		echo
		echo 'Starting WireGuard setup using default options.'
	fi
}

detect_ip() {
	# If system has a single IPv4, it is selected automatically.
	if [[ $(ip -4 addr | grep inet | grep -vEc '127(\.[0-9]{1,3}){3}') -eq 1 ]]; then
		ip=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}')
	else
		# Use the IP address on the default route
		ip=$(ip -4 route get 1 | sed 's/ uid .*//' | awk '{print $NF;exit}' 2>/dev/null)
		if ! check_ip "$ip"; then
			ip_match=0
			if [ -n "$get_public_ip" ]; then
				ip_list=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}')
				while IFS= read -r line; do
					if [ "$line" = "$get_public_ip" ]; then
						ip_match=1
						ip="$line"
					fi
				done <<< "$ip_list"
			fi
			if [ "$ip_match" = 0 ]; then
				if [ "$auto" = 0 ]; then
					echo
					echo "Which IPv4 address should be used?"
					number_of_ip=$(ip -4 addr | grep inet | grep -vEc '127(\.[0-9]{1,3}){3}')
					ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | nl -s ') '
					read -rp "IPv4 address [1]: " ip_number
					until [[ -z "$ip_number" || "$ip_number" =~ ^[0-9]+$ && "$ip_number" -le "$number_of_ip" ]]; do
						echo "$ip_number: invalid selection."
						read -rp "IPv4 address [1]: " ip_number
					done
					[[ -z "$ip_number" ]] && ip_number=1
				else
					ip_number=1
				fi
				ip=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | sed -n "$ip_number"p)
			fi
		fi
	fi
	if ! check_ip "$ip"; then
		echo "Error: Could not detect this server's IP address." >&2
		echo "Abort. No changes were made." >&2
		exit 1
	fi
}

show_config() {
	if [ "$auto" != 0 ]; then
		echo
		printf '%s' "Server IP: "
		[ -n "$public_ip" ] && printf '%s\n' "$public_ip" || printf '%s\n' "$ip"
		echo "Port: UDP/51820"
		echo "Client name: client"
		echo "Client DNS: Google Public DNS"
	fi
}

select_port() {
	if [ "$auto" = 0 ]; then
		echo
		echo "What port should WireGuard listen to?"
		read -rp "Port [51820]: " port
		until [[ -z "$port" || "$port" =~ ^[0-9]+$ && "$port" -le 65535 ]]; do
			echo "$port: invalid port."
			read -rp "Port [51820]: " port
		done
		[[ -z "$port" ]] && port=51820
	else
		port=51820
	fi
}

enter_custom_dns() {
	read -rp "Enter primary DNS server: " dns1
	until check_ip "$dns1"; do
		echo "Invalid DNS server."
		read -rp "Enter primary DNS server: " dns1
	done
	read -rp "Enter secondary DNS server (Enter to skip): " dns2
	until [ -z "$dns2" ] || check_ip "$dns2"; do
		echo "Invalid DNS server."
		read -rp "Enter secondary DNS server (Enter to skip): " dns2
	done
}

set_client_name() {
	# Allow a limited set of characters to avoid conflicts
	client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client")
}

enter_client_name() {
	if [ "$auto" = 0 ]; then
		echo
		echo "Enter a name for the first client:"
		read -rp "Name [client]: " unsanitized_client
		set_client_name
		[[ -z "$client" ]] && client=client
	else
		client=client
	fi
}

enter_public_ip() {
	echo
	echo "What is the public IPv4 address?"
	read -rp "Public IPv4 address: " public_ip
	until check_ip "$public_ip"; do
		echo "Invalid input."
		read -rp "Public IPv4 address: " public_ip
	done
}

abort_and_exit() {
	echo "Abort. No changes were made." >&2
	exit 1
}

confirm_setup() {
	if [ "$auto" = 0 ]; then
		printf "Do you want to continue? [Y/n] "
		read -r response
		case $response in
			[yY][eE][sS]|[yY]|'')
				:
				;;
			*)
				abort_and_exit
				;;
		esac
	fi
}

new_client_dns() {
	if [ "$auto" = 0 ]; then
		echo
		echo "Select a DNS server for the client:"
		echo "   1) Current system resolvers"
		echo "   2) Google Public DNS"
		echo "   3) Cloudflare DNS"
		echo "   4) OpenDNS"
		echo "   5) Quad9"
		echo "   6) AdGuard DNS"
		echo "   7) Custom"
		read -rp "DNS server [2]: " dns
		until [[ -z "$dns" || "$dns" =~ ^[1-7]$ ]]; do
			echo "$dns: invalid selection."
			read -rp "DNS server [2]: " dns
		done
	else
		dns=2
	fi
		# DNS
	case "$dns" in
		1)
			# Locate the proper resolv.conf
			# Needed for systems running systemd-resolved
			if grep '^nameserver' "/etc/resolv.conf" | grep -qv '127.0.0.53' ; then
				resolv_conf="/etc/resolv.conf"
			else
				resolv_conf="/run/systemd/resolve/resolv.conf"
			fi
			# Extract nameservers and provide them in the required format
			dns=$(grep -v '^#\|^;' "$resolv_conf" | grep '^nameserver' | grep -v '127.0.0.53' | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | xargs | sed -e 's/ /, /g')
		;;
		2|"")
			dns="8.8.8.8, 8.8.4.4"
		;;
		3)
			dns="1.1.1.1, 1.0.0.1"
		;;
		4)
			dns="208.67.222.222, 208.67.220.220"
		;;
		5)
			dns="9.9.9.9, 149.112.112.112"
		;;
		6)
			dns="94.140.14.14, 94.140.15.15"
		;;
		7)
			enter_custom_dns
			if [ -n "$dns2" ]; then
				dns="$dns1, $dns2"
			else
				dns="$dns1"
			fi
		;;
	esac
}

get_export_dir() {
	export_to_home_dir=0
	export_dir=~/
	if [ -n "$SUDO_USER" ] && getent group "$SUDO_USER" >/dev/null 2>&1; then
		user_home_dir=$(getent passwd "$SUDO_USER" 2>/dev/null | cut -d: -f6)
		if [ -d "$user_home_dir" ] && [ "$user_home_dir" != "/" ]; then
			export_dir="$user_home_dir/"
			export_to_home_dir=1
		fi
	fi
}

new_client_setup() {
	get_export_dir
	# Given a list of the assigned internal IPv4 addresses, obtain the lowest still
	# available octet. Important to start looking at 2, because 1 is our gateway.
	octet=2
	while grep AllowedIPs /etc/wireguard/wg0.conf | cut -d "." -f 4 | cut -d "/" -f 1 | grep -q "$octet"; do
		(( octet++ ))
	done
	# Don't break the WireGuard configuration in case the address space is full
	if [[ "$octet" -eq 255 ]]; then
		exiterr "253 clients are already configured. The WireGuard internal subnet is full!"
	fi
	key=$(wg genkey)
	psk=$(wg genpsk)
	# Configure client in the server
	cat << EOF >> /etc/wireguard/wg0.conf
# BEGIN_PEER $client
[Peer]
PublicKey = $(wg pubkey <<< "$key")
PresharedKey = $psk
AllowedIPs = 10.7.0.$octet/32$(grep -q 'fddd:2c4:2c4:2c4::1' /etc/wireguard/wg0.conf && echo ", fddd:2c4:2c4:2c4::$octet/128")
# END_PEER $client
EOF
	# Create client configuration
	cat << EOF > "$export_dir$client".conf
[Interface]
Address = 10.7.0.$octet/24$(grep -q 'fddd:2c4:2c4:2c4::1' /etc/wireguard/wg0.conf && echo ", fddd:2c4:2c4:2c4::$octet/64")
DNS = $dns
PrivateKey = $key

[Peer]
PublicKey = $(grep PrivateKey /etc/wireguard/wg0.conf | cut -d " " -f 3 | wg pubkey)
PresharedKey = $psk
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = $(grep '^# ENDPOINT' /etc/wireguard/wg0.conf | cut -d " " -f 3):$(grep ListenPort /etc/wireguard/wg0.conf | cut -d " " -f 3)
PersistentKeepalive = 25
EOF
	if [ "$export_to_home_dir" = 1 ]; then
		chown "$SUDO_USER:$SUDO_USER" "$export_dir$client".conf
	fi
	chmod 600 "$export_dir$client".conf
}

update_sysctl() {
	mkdir -p /etc/sysctl.d
	conf_fwd="/etc/sysctl.d/99-wireguard-forward.conf"
	conf_opt="/etc/sysctl.d/99-wireguard-optimize.conf"
	# Enable net.ipv4.ip_forward for the system
	echo 'net.ipv4.ip_forward=1' > "$conf_fwd"
	if [[ -n "$ip6" ]]; then
		# Enable net.ipv6.conf.all.forwarding for the system
		echo "net.ipv6.conf.all.forwarding=1" >> "$conf_fwd"
	fi
	# Optimize sysctl settings such as TCP buffer sizes
	base_url="https://github.com/hwdsl2/vpn-extras/releases/download/v1.0.0"
	conf_url="$base_url/sysctl-wg-$os"
	[ "$auto" != 0 ] && conf_url="${conf_url}-auto"
	wget -t 3 -T 30 -q -O "$conf_opt" "$conf_url" 2>/dev/null \
		|| curl -m 30 -fsL "$conf_url" -o "$conf_opt" 2>/dev/null \
		|| { /bin/rm -f "$conf_opt"; touch "$conf_opt"; }
	# Enable TCP BBR congestion control if kernel version >= 4.20
	if modprobe -q tcp_bbr \
		&& printf '%s\n%s' "4.20" "$(uname -r)" | sort -c -V \
		&& [ -f /proc/sys/net/ipv4/tcp_congestion_control ]; then
cat >> "$conf_opt" <<'EOF'
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOF
	fi
	# Apply sysctl settings
	sysctl -e -q -p "$conf_fwd"
	sysctl -e -q -p "$conf_opt"
}

show_header() {
cat <<'EOF'

WireGuard Script
https://github.com/hwdsl2/wireguard-install
EOF
}

show_header2() {
cat <<'EOF'

Copyright (c) 2022-2023 Lin Song
Copyright (c) 2020-2023 Nyr
EOF
}

show_usage() {
	if [ -n "$1" ]; then
		echo "Error: $1" >&2
	fi
	show_header
	show_header2
cat 1>&2 <<EOF

Usage: bash $0 [options]

Options:
  --auto      auto install WireGuard using default options
  -h, --help  show this help message and exit

To customize install options, run this script without arguments.
EOF
	exit 1
}

wgsetup() {

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

if [ "$(id -u)" != 0 ]; then
	exiterr "This installer must be run as root. Try 'sudo bash $0'"
fi

# Detect Debian users running the script with "sh" instead of bash
if readlink /proc/$$/exe | grep -q "dash"; then
	exiterr 'This installer needs to be run with "bash", not "sh".'
fi

# Detect OpenVZ 6
if [[ $(uname -r | cut -d "." -f 1) -eq 2 ]]; then
	exiterr "The system is running an old kernel, which is incompatible with this installer."
fi

if systemd-detect-virt -cq 2>/dev/null; then
	exiterr "This system is running inside a container, which is not supported by this installer."
fi

auto=0
if [[ ! -e /etc/wireguard/wg0.conf ]]; then
	while [ "$#" -gt 0 ]; do
		case $1 in
			--auto)
				auto=1
				shift
				;;
			-h|--help)
				show_usage
				;;
			*)
				show_usage "Unknown parameter: $1"
				;;
		esac
	done
	(
		set -x
		apk update >/dev/null
	) || exiterr2
	install_iproute
	show_start_setup
	enter_public_ip
	detect_ip
	show_config
	select_port
	enter_client_name
	new_client_dns
	if [ "$auto" = 0 ]; then
		echo
		echo "WireGuard installation is ready to begin."
	fi
	confirm_setup
	echo
	echo "Installing WireGuard, please wait..."
	install_wg_tool
	install_nftables
	[ ! -d /etc/wireguard ] && exiterr2
	# Generate wg0.conf
	cat << EOF > /etc/wireguard/wg0.conf
# Do not alter the commented lines
# They are used by wireguard-install
# ENDPOINT $([[ -n "$public_ip" ]] && echo "$public_ip" || echo "$ip")

[Interface]
Address = 10.7.0.1/24$([[ -n "$ip6" ]] && echo ", fddd:2c4:2c4:2c4::1/64")
PrivateKey = $(wg genkey)
ListenPort = $port

EOF
	chmod 600 /etc/wireguard/wg0.conf
	update_sysctl

	## OpenRC service
	echo "#!/sbin/openrc-run

description=\"Manage IP packets for WireGuard service.\"

start()
{" > /etc/init.d/$wgfw
	if [[ $firewall == "iptables" ]]; then
		echo "
	iptables -t nat -A POSTROUTING -s 10.7.0.0/24 ! -d 10.7.0.0/24 -j SNAT --to $ip
	iptables -I INPUT -p udp --dport $port -j ACCEPT
	iptables -I FORWARD -s 10.7.0.0/24 -j ACCEPT
	iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
" >> /etc/init.d/$wgfw
	elif [[ $firewall == "nftables" ]]; then
		echo "
	nft add table ip wg-nat
	nft add chain ip wg-nat PREROUTING \"{ type nat hook prerouting priority -100; policy accept; }\"
	nft add chain ip wg-nat INPUT \"{ type nat hook input priority 100; policy accept; }\"
	nft add chain ip wg-nat OUTPUT \"{ type nat hook output priority -100; policy accept; }\"
	nft add chain ip wg-nat POSTROUTING \"{ type nat hook postrouting priority 100; policy accept; }\"
	nft add rule ip wg-nat POSTROUTING ip saddr 10.7.0.0/24 ip daddr != 10.7.0.0/24 counter snat to $ip
	nft add table ip wg-filter
	nft add chain ip wg-filter INPUT \"{ type filter hook input priority 0; policy accept; }\"
	nft add chain ip wg-filter FORWARD \"{ type filter hook forward priority 0; policy accept; }\"
	nft add chain ip wg-filter OUTPUT \"{ type filter hook output priority 0; policy accept; }\"
	nft add rule ip wg-filter INPUT udp dport $port counter accept
	nft add rule ip wg-filter FORWARD ct state related,established counter accept
	nft add rule ip wg-filter FORWARD ip saddr 10.7.0.0/24 counter accept
" >> /etc/init.d/$wgfw
	fi
		echo "
	default_start
}

stop()
{" >> /etc/init.d/$wgfw
	if [[ $firewall == "iptables" ]]; then
		echo "
	iptables -D INPUT -p udp --dport $port -j ACCEPT
	iptables -D FORWARD -s 10.7.0.0/24 -j ACCEPT
	iptables -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
	iptables -t nat -D POSTROUTING -s 10.7.0.0/24 ! -d 10.7.0.0/24 -j SNAT --to $ip
" >> /etc/init.d/$wgfw
	elif [[ $firewall == "nftables" ]]; then
		echo "
	nft delete table wg-nat
	nft delete table wg-filter
" >> /etc/init.d/$wgfw
	fi
	echo "
	default_stop
}
" >> /etc/init.d/$wgfw
	chmod a+x /etc/init.d/$wgfw
	(
		set -x
		rc-update add $wgfw default >/dev/null 2>&1
		rc-service $wgfw start
	)
	# Generates the custom client.conf
	new_client_setup
	# Enable and start the wg-quick service
	(
		set -x
		wg-quick up wg0
	)
	# If the kernel module didn't load, system probably had an outdated kernel
	# We'll try to help, but will not force a kernel upgrade upon the user
	if ! modprobe -nq wireguard; then
		echo "Warning!"
		echo "Installation was finished, but the WireGuard kernel module could not load."
		echo "Reboot the system to load the most recent kernel."
	else
		echo "Finished!"
	fi
	echo
	echo "The client configuration is available in: $export_dir$client.conf"
	echo "New clients can be added by running this script again."
else
	show_header
	echo
	echo "WireGuard is already installed."
	echo
	echo "Select an option:"
	echo "   1) Add a new client"
	echo "   2) List existing clients"
	echo "   3) Remove an existing client"
	echo "   4) Remove WireGuard"
	echo "   5) Exit"
	read -rp "Option: " option
	until [[ "$option" =~ ^[1-5]$ ]]; do
		echo "$option: invalid selection."
		read -rp "Option: " option
	done
	case "$option" in
		1)
			echo
			echo "Provide a name for the client:"
			read -rp "Name: " unsanitized_client
			[ -z "$unsanitized_client" ] && abort_and_exit
			set_client_name
			while [[ -z "$client" ]] || grep -q "^# BEGIN_PEER $client$" /etc/wireguard/wg0.conf; do
				echo "$client: invalid name."
				read -rp "Name: " unsanitized_client
				[ -z "$unsanitized_client" ] && abort_and_exit
				set_client_name
			done
			new_client_dns
			new_client_setup
			# Append new client configuration to the WireGuard interface
			wg addconf wg0 <(sed -n "/^# BEGIN_PEER $client/,/^# END_PEER $client/p" /etc/wireguard/wg0.conf)
			echo "$client added. Configuration available in: $export_dir$client.conf"
			exit
		;;
		2)
			echo
			echo "Checking for existing client(s)..."
			number_of_clients=$(grep -c '^# BEGIN_PEER' /etc/wireguard/wg0.conf)
			if [[ "$number_of_clients" = 0 ]]; then
				echo
				echo "There are no existing clients!"
				exit
			fi
			echo
			grep '^# BEGIN_PEER' /etc/wireguard/wg0.conf | cut -d ' ' -f 3 | nl -s ') '
			if [ "$number_of_clients" = 1 ]; then
				printf '\n%s\n' "Total: 1 client"
			elif [ -n "$number_of_clients" ]; then
				printf '\n%s\n' "Total: $number_of_clients clients"
			fi
		;;
		3)
			number_of_clients=$(grep -c '^# BEGIN_PEER' /etc/wireguard/wg0.conf)
			if [[ "$number_of_clients" = 0 ]]; then
				echo
				echo "There are no existing clients!"
				exit
			fi
			echo
			echo "Select the client to remove:"
			grep '^# BEGIN_PEER' /etc/wireguard/wg0.conf | cut -d ' ' -f 3 | nl -s ') '
			read -rp "Client: " client_number
			[ -z "$client_number" ] && abort_and_exit
			until [[ "$client_number" =~ ^[0-9]+$ && "$client_number" -le "$number_of_clients" ]]; do
				echo "$client_number: invalid selection."
				read -rp "Client: " client_number
				[ -z "$client_number" ] && abort_and_exit
			done
			client=$(grep '^# BEGIN_PEER' /etc/wireguard/wg0.conf | cut -d ' ' -f 3 | sed -n "$client_number"p)
			echo
			read -rp "Confirm $client removal? [y/N]: " remove
			until [[ "$remove" =~ ^[yYnN]*$ ]]; do
				echo "$remove: invalid selection."
				read -rp "Confirm $client removal? [y/N]: " remove
			done
			if [[ "$remove" =~ ^[yY]$ ]]; then
				echo
				echo "Removing $client..."
				# The following is the right way to avoid disrupting other active connections:
				# Remove from the live interface
				wg set wg0 peer "$(sed -n "/^# BEGIN_PEER $client$/,\$p" /etc/wireguard/wg0.conf | grep -m 1 PublicKey | cut -d " " -f 3)" remove
				# Remove from the configuration file
				sed -i "/^# BEGIN_PEER $client$/,/^# END_PEER $client$/d" /etc/wireguard/wg0.conf
				get_export_dir
				wg_file="$export_dir$client.conf"
				if [ -f "$wg_file" ]; then
					echo "Removing $wg_file..."
					rm -f "$wg_file"
				fi
				echo
				echo "$client removed!"
			else
				echo
				echo "$client removal aborted!"
			fi
			exit
		;;
		4)
			echo
			read -rp "Confirm WireGuard removal? [y/N]: " remove
			until [[ "$remove" =~ ^[yYnN]*$ ]]; do
				echo "$remove: invalid selection."
				read -rp "Confirm WireGuard removal? [y/N]: " remove
			done
			if [[ "$remove" =~ ^[yY]$ ]]; then
				echo
				echo "Removing WireGuard, please wait..."
				port=$(grep '^ListenPort' /etc/wireguard/wg0.conf | cut -d " " -f 3)
				rc-update delete $wgfw default
				rc-service $wgfw stop
				rm -f /etc/init.d/$wgfw
				wg-quick down wg0
				rm /etc/wireguard/wg0.conf
				rm -f /etc/sysctl.d/99-wireguard-forward.conf /etc/sysctl.d/99-wireguard-optimize.conf
				if [ ! -f /usr/sbin/openvpn ] && [ ! -f /usr/sbin/ipsec ] \
					&& [ ! -f /usr/local/sbin/ipsec ]; then
					echo 0 > /proc/sys/net/ipv4/ip_forward
					echo 0 > /proc/sys/net/ipv6/conf/all/forwarding
				fi
				read -rp "Remove wireguard-tools [N]: " rm_wg_tools
				[[ -z "$rm_wg_tools" ]] && rm_wg_tools=N
				until [[ "$rm_wg_tools" =~ ^[yYnN]*$ ]]; do
					echo "invalid selection."
					read -rp "Remove wireguard-tools [y/N]: " rm_wg_tools
				done
				if [[ "$rm_wg_tools" =~ ^[yY]*$ ]]; then
					echo "removing wg-tools"
					apk del wireguard-tools >/dev/null
				else
					echo "skipped"
				fi
				echo "WireGuard removed!"
			else
				echo
				echo "WireGuard removal aborted!"
			fi
			exit
		;;
		5)
			exit
		;;
	esac
fi
}

## Defer setup until we have the complete script
wgsetup "$@"

exit 0
