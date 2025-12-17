#!/bin/bash

# --- CONFIGURATION ---
INET_INT="wlan0"      # WAN: Connects to Home Wi-Fi (Internet Source)
WLAN_INT="wlan1"      # LAN: Creates Hotspot (Access Point)
GATEWAY_IP="192.168.50.1"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
  echo "[-] Please run as root (sudo ./start_router.sh)"
  exit 1
fi

echo "=========================================================="
echo "[*] Setting up Smart IPS Router"
echo "[*] Internet Source (WAN): $INET_INT"
echo "[*] Hotspot Interface (LAN): $WLAN_INT"
echo "=========================================================="

# --- 1. CLEANUP & PREP ---
echo "[-] Stopping conflicting services..."
systemctl stop NetworkManager
systemctl stop wpa_supplicant

# Kill any lingering processes to free up the cards
killall wpa_supplicant 2>/dev/null
killall dnsmasq 2>/dev/null
killall hostapd 2>/dev/null
killall dhclient 2>/dev/null

# Unblock radio just in case
rfkill unblock wlan

# --- 2. CONNECT TO INTERNET (WAN) ---
echo "[-] Connecting $INET_INT to Home Wi-Fi..."
# Bring interface up
ip link set $INET_INT up

# Connect using the supplicant file you created
wpa_supplicant -B -i $INET_INT -c wlan0_supplicant.conf

# Wait a moment for association
echo "[-] Waiting for Wi-Fi association..."
sleep 5

# Get an IP address from your home router
echo "[-] Requesting IP address for $INET_INT..."
dhclient $INET_INT

# Verify connection
if ! ip addr show $INET_INT | grep -q "inet"; then
    echo "[!] ERROR: $INET_INT failed to get an IP address."
    echo "[!] Check your password in wlan0_supplicant.conf"
    exit 1
fi
echo "[+] Internet connected!"

# --- 3. CONFIGURE HOTSPOT (LAN) ---
echo "[-] Configuring Hotspot interface $WLAN_INT..."
# Flush old IPs to prevent "Address already assigned" error
ip addr flush dev $WLAN_INT
ip link set $WLAN_INT down
ip link set $WLAN_INT up

# Assign the Gateway IP
ip addr add $GATEWAY_IP/24 dev $WLAN_INT

# --- 4. ENABLE ROUTING & NAT ---
echo "[-] Setting up Firewall & NAT..."
# Enable Kernel Forwarding
sysctl -w net.ipv4.ip_forward=1 > /dev/null
# Enable IPv6 Forwarding
sysctl -w net.ipv6.conf.all.forwarding=1 > /dev/null

# Flush old iptables rules
iptables -F
iptables -t nat -F

# NAT Masquerading (The magic that shares the internet)
iptables -t nat -A POSTROUTING -o $INET_INT -j MASQUERADE
iptables -A FORWARD -i $WLAN_INT -o $INET_INT -j ACCEPT
iptables -A FORWARD -i $INET_INT -o $WLAN_INT -m state --state RELATED,ESTABLISHED -j ACCEPT

# --- 5. START SERVICES ---
echo "[+] Starting DHCP Server (dnsmasq)..."
# Ensure dnsmasq.conf is set to interface=wlan1
dnsmasq -C dnsmasq.conf -d > dnsmasq.log 2>&1 &
DNSMASQ_PID=$!

echo "[+] Starting Wi-Fi Access Point (hostapd)..."
# Ensure hostapd.conf is set to interface=wlan1
hostapd hostapd.conf > hostapd.log 2>&1 &
HOSTAPD_PID=$!

echo "=========================================================="
echo "[*] Router is ONLINE."
echo "[*] Connect your devices to 'Kali_Smart_IPS'"
echo "=========================================================="
echo "Press Ctrl+C to stop services and clean up."

# Wait loop to keep script running
trap "kill $DNSMASQ_PID; kill $HOSTAPD_PID; echo 'Stopping...'; exit" SIGINT
wait