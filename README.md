# 🛡️ Smart IPS: Home IoT Intrusion Prevention System

**Smart IPS** is a lightweight, open-source Intrusion Prevention System (IPS) designed to secure home networks and IoT devices. Built for Linux environments (like Raspberry Pi or Kali Linux), it functions as a secure Wi-Fi router that monitors traffic in real-time, detects anomalies, and allows users to block threats instantly via a web dashboard.

## 🚀 Features

* **Real-Time Traffic Monitoring**: Visualizes bandwidth usage (KB/s) for every connected device using interactive charts.
* **Web-Based Dashboard**: A user-friendly interface built with Python Flask to manage the network without touching the command line.
* **Firewall Management**: Manually block or unblock devices with a "Kill Switch" that instantly updates `iptables`.
* **Automated IPS Engine**:
    * **Anomaly Detection**: Automatically flags or throttles devices exceeding defined bandwidth thresholds.
    * **Signature Detection**: Alerts on connections to non-whitelisted IP addresses.
* **Device Fingerprinting**: Identifies device manufacturers (Apple, Samsung, Espressif, etc.) using MAC address lookup.
* **Persistent Logging**: Stores historical traffic data, alerts, and flow logs in a SQLite database.

## 🛠️ System Architecture

The system operates by turning a Linux host into a Wi-Fi Access Point (AP). It sits between your IoT devices and the internet.

1.  **Network Layer**: Uses `hostapd` to create the hotspot and `dnsmasq` for DHCP/DNS. `iptables` handles NAT and packet filtering.
2.  **Backend (The "Brain")**: `device_manager.py` continuously polls kernel connection tracking (`conntrack`) to calculate data rates and enforce IPS rules.
3.  **Frontend (The "Face")**: `app.py` serves the HTML5 dashboard and communicates with the backend via a shared SQLite database.

## 📋 Prerequisites

### Hardware
* A Linux-based computer (Raspberry Pi 3/4 recommended, or a laptop with Kali Linux/Ubuntu).
* **Two Network Interfaces**:
    * `wlan0`: Connected to the internet (Home Wi-Fi).
    * `wlan1`: USB Wi-Fi Adapter (must support **AP Mode** / Packet Injection) to act as the hotspot.

### Software
* Python 3.x
* Root privileges (required for `iptables` and network configuration).

## 📥 Installation

1.  **Clone the Repository**
    ```bash
    git clone [https://github.com/yourusername/smart-ips.git](https://github.com/yourusername/smart-ips.git)
    cd smart-ips
    ```

2.  **Install System Dependencies**
    ```bash
    sudo apt update
    sudo apt install hostapd dnsmasq iptables python3-pip
    ```

3.  **Install Python Libraries**
    ```bash
    pip3 install flask mac-vendor-lookup
    ```

4.  **Configure Network Interfaces**
    * Edit `hostapd.conf` and `start_router.sh` if your interface names differ from `wlan0` (WAN) and `wlan1` (LAN).

## ⚡ Usage

To run the system, you need to start three components in separate terminal windows (or use a service manager like `systemd`).

### Step 1: Start the Router
Initializes the Wi-Fi hotspot and enables IP forwarding.
```bash
sudo ./start_router.sh
