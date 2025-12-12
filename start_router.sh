#!/bin/bash

# Configuration
WLAN_INT="wlan0"      # Your Wi-Fi Interface (Hotspot)
INET_INT="eth0"       # Your Internet Source (Ethernet cable)
GATEWAY_IP="192.168.50.1"

# Check if running as root
if [ "$EUID" -ne 0 ]
  then echo "[-] Please run as root (sudo ./start_router.sh)"
  exit
fi

echo "[*] Setting up Smart IPS Router..."

# 1. Stop conflicting services (Crucial on Kali)
echo "[-] Killing NetworkManager and wpa_supplicant..."
systemctl stop NetworkManager
airmon-ng check kill > /dev/null 2>&1

echo "Killing interfering processes..."
sudo airmon-ng check kill
echo "[-] Reviving Internet on eth0..."
dhclient eth0
# 2. Configure Interface
echo "[-] Configuring $WLAN_INT IP address..."
ifconfig $WLAN_INT down
ifconfig $WLAN_INT up $GATEWAY_IP netmask 255.255.255.0

# 3. Enable IP Forwarding (The routing part)
echo "[-] Enabling IP Forwarding..."
sysctl -w net.ipv4.ip_forward=1 > /dev/null

# 4. Setup NAT (Internet Sharing)
echo "[-] Setting up iptables NAT rules..."
# Flush old rules
iptables -F
iptables -t nat -F

# Create NAT from wlan0 -> eth0
iptables -t nat -A POSTROUTING -o $INET_INT -j MASQUERADE
iptables -A FORWARD -i $WLAN_INT -o $INET_INT -j ACCEPT
iptables -A FORWARD -i $INET_INT -o $WLAN_INT -m state --state RELATED,ESTABLISHED -j ACCEPT

# 5. Start Services
echo "[+] Starting dnsmasq (DHCP)..."
dnsmasq -C dnsmasq.conf -d > dnsmasq.log 2>&1 &
DNSMASQ_PID=$!

echo "[+] Starting hostapd (Wi-Fi)..."
hostapd hostapd.conf > hostapd.log 2>&1 &
HOSTAPD_PID=$!

echo "[*] Router is ONLINE. Connect to 'Kali_Smart_IPS'."
echo "[*] Logs are being saved to hostapd.log and dnsmasq.log"
echo "Press Ctrl+C to stop."

# Wait loop to keep script running
trap "kill $DNSMASQ_PID; kill $HOSTAPD_PID; echo 'Stopping...'; exit" SIGINT
wait