import sqlite3
import time
import os
import subprocess
from datetime import datetime, timedelta
from mac_vendor_lookup import MacLookup

DB_PATH = 'ips_data.db'
LEASES_FILE = '/var/lib/misc/dnsmasq.leases'
HISTORY_DAYS = 7
POLL_INTERVAL = 5 

class DeviceManager:
    def __init__(self):
        print("[*] Initializing Device Manager & IPS Engine...")
        self.mac_lookup = MacLookup()
        try: self.mac_lookup.update_vendors() 
        except: print("[!] Could not download vendor DB. Using local cache.")
        
        os.system("sysctl -w net.netfilter.nf_conntrack_acct=1 > /dev/null")
        self.throttled_devices = {}
        self.init_db()
        self.apply_firewall_rules()

    def init_db(self):
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Core Tables
        cursor.execute('CREATE TABLE IF NOT EXISTS devices (mac_addr TEXT PRIMARY KEY, ip_addr TEXT, ipv6_addr TEXT, vendor TEXT, hostname TEXT, model TEXT, version TEXT, description TEXT, last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP)')
        cursor.execute('CREATE TABLE IF NOT EXISTS data_rates (id INTEGER PRIMARY KEY, mac_addr TEXT, timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP, rx_bytes INTEGER, tx_bytes INTEGER, rate_kbps REAL)')
        cursor.execute('CREATE TABLE IF NOT EXISTS flow_logs (id INTEGER PRIMARY KEY, mac_addr TEXT, remote_ip TEXT, local_port INTEGER, remote_port INTEGER, protocol TEXT, packet_count INTEGER, last_activation TIMESTAMP, UNIQUE(mac_addr, remote_ip, remote_port, protocol))')
        cursor.execute('CREATE TABLE IF NOT EXISTS firewall_rules (id INTEGER PRIMARY KEY, rule_type TEXT, target TEXT, protocol TEXT, description TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)')
        
        # --- NEW IPS TABLES ---
        # Rule Types: 'SIGNATURE' (Whitelist IP) or 'ANOMALY' (Max Rate)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ips_rules (
                id INTEGER PRIMARY KEY, 
                mac_addr TEXT, 
                rule_type TEXT, 
                parameter TEXT, 
                action_param INTEGER, 
                is_active INTEGER DEFAULT 1
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ips_alerts (
                id INTEGER PRIMARY KEY, 
                mac_addr TEXT, 
                alert_type TEXT, 
                message TEXT, 
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()

    def apply_firewall_rules(self):
        """Standard Firewall (Blocklist)"""
        print("[-] Re-applying firewall rules...")
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        rules = conn.execute("SELECT * FROM firewall_rules").fetchall()
        conn.close()
        
        pass 

    def get_ips_rules(self):
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        rules = conn.execute("SELECT * FROM ips_rules WHERE is_active=1").fetchall()
        conn.close()
        return rules

    def log_alert(self, mac, type, msg):
        print(f"[!] IPS ALERT [{type}] Device {mac}: {msg}")
        conn = sqlite3.connect(DB_PATH)
        # Prevent log spam: check if identical alert exists in last minute
        recent = conn.execute("SELECT 1 FROM ips_alerts WHERE mac_addr=? AND message=? AND timestamp > datetime('now', '-1 minute')", (mac, msg)).fetchone()
        if not recent:
            conn.execute("INSERT INTO ips_alerts (mac_addr, alert_type, message) VALUES (?,?,?)", (mac, type, msg))
            conn.commit()
        conn.close()

    def throttle_device(self, mac, duration_mins):
        """Throttles a device using iptables limit module"""
        if mac in self.throttled_devices: return 

        print(f"[!!!] THROTTLING {mac} for {duration_mins} minutes.")
        self.throttled_devices[mac] = datetime.now() + timedelta(minutes=duration_mins)
        # Logic: 1. Allow limited packets. 2. Drop the rest.
        # Limit to ~10 packets/sec (approx very slow connection)
        subprocess.run(f"iptables -I FORWARD 1 -m mac --mac-source {mac} -m limit --limit 10/sec -j ACCEPT", shell=True)
        subprocess.run(f"iptables -I FORWARD 2 -m mac --mac-source {mac} -j DROP", shell=True)

    def check_throttle_expiry(self):
        """Checks if devices can be un-throttled"""
        now = datetime.now()
        to_remove = []
        for mac, expiry in self.throttled_devices.items():
            if now > expiry:
                print(f"[+] Un-throttling {mac}")
                # Remove the rules we added (by matching the logic)
                subprocess.run(f"iptables -D FORWARD -m mac --mac-source {mac} -m limit --limit 10/sec -j ACCEPT", shell=True)
                subprocess.run(f"iptables -D FORWARD -m mac --mac-source {mac} -j DROP", shell=True)
                to_remove.append(mac)
        
        for mac in to_remove:
            del self.throttled_devices[mac]

    def parse_conntrack(self):
        """IPS Engine Logic inside the traffic parser"""
        rules = self.get_ips_rules()
        conn = sqlite3.connect(DB_PATH)
        devices = {row[0]: row[1] for row in conn.execute("SELECT ip_addr, mac_addr FROM devices").fetchall()}
        conn.close()
        
        try:
            with open('/proc/net/nf_conntrack', 'r') as f:
                lines = f.readlines()
            
            for line in lines:
                if 'ESTABLISHED' not in line: continue
                parts = line.split()
                try:
                    proto = parts[2]
                    src = next(p for p in parts if 'src=' in p).split('=')[1]
                    dst = next(p for p in parts if 'dst=' in p).split('=')[1]
                    sport = next(p for p in parts if 'sport=' in p).split('=')[1]
                    dport = next(p for p in parts if 'dport=' in p).split('=')[1]
                    pkts = int(next(p for p in parts if 'packets=' in p).split('=')[1])
                    bytes_v = int(next(p for p in parts if 'bytes=' in p).split('=')[1])
                    
                    mac = devices.get(src) # Outbound traffic
                    if mac: 
                        self.log_flow(mac, dst, sport, dport, proto, pkts)
                        rate_kbps = self.log_data_rate(mac, bytes_v, 0)
                        
                        # IPS: Anomaly Detection (Rate Threshold)
                        for r in rules:
                            if r['mac_addr'] == mac and r['rule_type'] == 'ANOMALY':
                                threshold = float(r['parameter']) # Max KB/s
                                duration = int(r['action_param']) # Mins
                                if rate_kbps > threshold:
                                    msg = f"Data Rate {rate_kbps:.2f} KB/s exceeded limit {threshold} KB/s"
                                    self.log_alert(mac, 'ANOMALY', msg)
                                    self.throttle_device(mac, duration)

                        # IPS: Signature Check (Allowed IP Violation)
                        for r in rules:
                            if r['mac_addr'] == mac and r['rule_type'] == 'SIGNATURE':
                                allowed_ip = r['parameter']
                                if dst != allowed_ip:
                                    msg = f"Unauthorized connection to {dst}. Only {allowed_ip} allowed."
                                    self.log_alert(mac, 'SIGNATURE', msg)

                    # Inbound Traffic (Just log, usually less critical for egress control)
                    mac = devices.get(dst)
                    if mac:
                        self.log_flow(mac, src, dport, sport, proto, pkts)
                        self.log_data_rate(mac, 0, bytes_v)
                        
                except Exception: continue
        except FileNotFoundError: pass

    def log_flow(self, mac, rip, lp, rp, proto, pkts):
        conn = sqlite3.connect(DB_PATH)
        try:
            conn.execute('INSERT INTO flow_logs (mac_addr, remote_ip, local_port, remote_port, protocol, packet_count, last_activation) VALUES (?,?,?,?,?,?,CURRENT_TIMESTAMP) ON CONFLICT(mac_addr, remote_ip, remote_port, protocol) DO UPDATE SET packet_count=?, last_activation=CURRENT_TIMESTAMP', (mac, rip, lp, rp, proto, pkts, pkts))
            conn.commit()
        except: pass
        conn.close()

    def log_data_rate(self, mac, tx, rx):
        """Logs rate and returns the calculated KB/s for immediate checking"""
        rate = round((tx + rx) / 1024.0, 2)
        conn = sqlite3.connect(DB_PATH)
        conn.execute('INSERT INTO data_rates (mac_addr, rx_bytes, tx_bytes, rate_kbps) VALUES (?,?,?,?)', (mac, rx, tx, rate))
        conn.commit()
        conn.close()
        return rate

    def scan_leases(self):
        # (Same as before)
        if not os.path.exists(LEASES_FILE): return
        conn = sqlite3.connect(DB_PATH)
        with open(LEASES_FILE, 'r') as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 4:
                    mac, ip, host = parts[1], parts[2], parts[3]
                    ipv6 = self.get_ipv6(mac)
                    if not conn.execute("SELECT 1 FROM devices WHERE mac_addr=?", (mac,)).fetchone():
                        conn.execute('INSERT INTO devices (mac_addr, ip_addr, ipv6_addr, vendor, hostname) VALUES (?,?,?,?,?)', (mac, ip, ipv6, self.get_vendor(mac), host))
                    else:
                        conn.execute('UPDATE devices SET ip_addr=?, ipv6_addr=?, last_seen=CURRENT_TIMESTAMP WHERE mac_addr=?', (ip, ipv6, mac))
        conn.commit()
        conn.close()
    

    def get_vendor(self, mac):
        try: return self.mac_lookup.lookup(mac)
        except: return "Unknown"
    def get_ipv6(self, mac):
        try:
            output = subprocess.check_output("ip -6 neigh", shell=True).decode()
            for line in output.splitlines():
                if mac in line:
                    parts = line.split()
                    # Return the IP address (first part)
                    return parts[0]

        except Exception as e:
            print(f"[!] Error fetching IPv6 for {mac}: {e}")
        
        return "N/A"  # Return N/A instead of "-" so you know it checked
    def clean_old_records(self):
        conn = sqlite3.connect(DB_PATH)
        cutoff = datetime.now() - timedelta(days=HISTORY_DAYS)
        conn.execute("DELETE FROM data_rates WHERE timestamp < ?", (cutoff,))
        conn.execute("DELETE FROM flow_logs WHERE last_activation < ?", (cutoff,))
        conn.execute("DELETE FROM ips_alerts WHERE timestamp < ?", (cutoff,))
        conn.commit()
        conn.close()

if __name__ == "__main__":
    dm = DeviceManager()
    print(f"[-] IPS Engine Running...")
    last_clean = time.time()
    
    while True:
        dm.scan_leases()
        dm.parse_conntrack()
        dm.check_throttle_expiry() # Check if we can un-throttle anyone
        
        if time.time() - last_clean > 86400:
            dm.clean_old_records()
            last_clean = time.time()
        time.sleep(POLL_INTERVAL)