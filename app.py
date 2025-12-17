from flask import Flask, render_template, redirect, url_for, request, jsonify
import sqlite3
import subprocess
import os
from datetime import datetime, timedelta

app = Flask(__name__)
DB_PATH = 'ips_data.db'
LOG_FILES = ['dnsmasq.log', 'hostapd.log']

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/')
def index():
    conn = get_db()
    # Fetch all devices
    devices_raw = conn.execute('SELECT * FROM devices').fetchall()
    conn.close()
    
    devices = []
    for dev in devices_raw:
        d = dict(dev)
        # Check if currently blocked in iptables
        try: 
            # Look for DROP rules matching this MAC
            subprocess.check_output(f"sudo iptables -L FORWARD -n | grep {d['mac_addr']}", shell=True, stderr=subprocess.DEVNULL)
            d['is_blocked'] = True
        except: 
            d['is_blocked'] = False
        devices.append(d)
        
    return render_template('index.html', devices=devices)

# --- IPS DASHBOARD ROUTES ---
@app.route('/ips')
def ips_dashboard():
    conn = get_db()
    # Get active Rules joined with Device info
    rules = conn.execute('''
        SELECT r.*, d.hostname, d.ip_addr 
        FROM ips_rules r 
        LEFT JOIN devices d ON r.mac_addr = d.mac_addr
    ''').fetchall()
    
    # Get Recent Alerts
    alerts = conn.execute('''
        SELECT a.*, d.hostname 
        FROM ips_alerts a 
        LEFT JOIN devices d ON a.mac_addr = d.mac_addr
        ORDER BY a.timestamp DESC LIMIT 50
    ''').fetchall()
    conn.close()
    return render_template('ips.html', rules=rules, alerts=alerts)

@app.route('/ips/add_rule', methods=['POST'])
def ips_add_rule():
    mac = request.form['mac_addr']
    r_type = request.form['rule_type']
    param = request.form['parameter']
    action = request.form['action_param']
    
    conn = get_db()
    conn.execute('INSERT INTO ips_rules (mac_addr, rule_type, parameter, action_param) VALUES (?, ?, ?, ?)',
                 (mac, r_type, param, action))
    conn.commit()
    conn.close()
    return redirect(url_for('ips_dashboard'))

@app.route('/ips/delete_rule/<int:rule_id>')
def ips_delete_rule(rule_id):
    conn = get_db()
    conn.execute('DELETE FROM ips_rules WHERE id = ?', (rule_id,))
    conn.commit()
    conn.close()
    return redirect(url_for('ips_dashboard'))

# --- FIREWALL ROUTES ---
@app.route('/firewall')
def firewall():
    conn = get_db()
    rules = conn.execute('SELECT * FROM firewall_rules ORDER BY created_at DESC').fetchall()
    conn.close()
    return render_template('firewall.html', rules=rules)

@app.route('/firewall/add', methods=['POST'])
def add_fw_rule():
    r_type = request.form['rule_type']
    target = request.form['target']
    proto = request.form['protocol']
    desc = request.form['description']
    
    # Apply to System (The "Real" Firewall)
    if r_type == 'IP':
        # Block traffic to/from this IP
        subprocess.run(f"sudo iptables -I FORWARD -s {target} -j DROP", shell=True)
        subprocess.run(f"sudo iptables -I FORWARD -d {target} -j DROP", shell=True)
    elif r_type == 'PORT':
        # Block TCP/UDP port
        p_flag = "tcp" if proto == "TCP" else "udp"
        if proto == "ALL":
             subprocess.run(f"sudo iptables -I FORWARD -p tcp --dport {target} -j DROP", shell=True)
             subprocess.run(f"sudo iptables -I FORWARD -p udp --dport {target} -j DROP", shell=True)
        else:
             subprocess.run(f"sudo iptables -I FORWARD -p {p_flag} --dport {target} -j DROP", shell=True)
             
    # Save to DB
    conn = get_db()
    conn.execute('INSERT INTO firewall_rules (rule_type, target, protocol, description) VALUES (?, ?, ?, ?)',
                 (r_type, target, proto, desc))
    conn.commit()
    conn.close()
    return redirect(url_for('firewall'))

@app.route('/firewall/delete/<int:rule_id>')
def delete_fw_rule(rule_id):
    conn = get_db()
    rule = conn.execute('SELECT * FROM firewall_rules WHERE id = ?', (rule_id,)).fetchone()
    
    if rule:
        # Remove from System (Using -D instead of -I)
        target = rule['target']
        if rule['rule_type'] == 'IP':
            subprocess.run(f"sudo iptables -D FORWARD -s {target} -j DROP", shell=True)
            subprocess.run(f"sudo iptables -D FORWARD -d {target} -j DROP", shell=True)
        # (Simplified for demo: Port removal logic would go here)
        
        conn.execute('DELETE FROM firewall_rules WHERE id = ?', (rule_id,))
        conn.commit()
    
    conn.close()
    return redirect(url_for('firewall'))

# --- DEVICE MANAGEMENT ROUTES ---
@app.route('/device/<mac>')
def device_detail(mac):
    conn = get_db()
    device = conn.execute('SELECT * FROM devices WHERE mac_addr = ?', (mac,)).fetchone()
    
    # Get recent flows for this device
    cutoff = datetime.now() - timedelta(days=7) # Default view
    flows = conn.execute('SELECT * FROM flow_logs WHERE mac_addr = ? AND last_activation > ? ORDER BY last_activation DESC LIMIT 100', (mac, cutoff)).fetchall()
    
    conn.close()
    return render_template('device_detail.html', device=device, flows=flows)

@app.route('/api/history/<mac>')
def api_history(mac):
    try:
        # Use float() to accept decimals like 0.041 (1 hour)
        days = float(request.args.get('days', 1))
    except ValueError:
        days = 1.0 # Fallback to 1 day if invalid
        
    cutoff = datetime.utcnow() - timedelta(days=days)

    
    conn = get_db()
    # Fetch data points
    data = conn.execute('SELECT timestamp, rate_kbps FROM data_rates WHERE mac_addr = ? AND timestamp > ? ORDER BY timestamp ASC', (mac, cutoff)).fetchall()
    conn.close()
    
    # Convert database rows to list of values
    labels = [
    row['timestamp'].replace(' ', 'T') + 'Z'
    for row in data
]

    values = [row['rate_kbps'] for row in data]
    
    return jsonify({'labels': labels, 'values': values})
@app.route('/admin/cleanup')
def admin_cleanup():
    action = request.args.get('action')
    conn = get_db()
    if action == 'clear_sys_logs': 
        for f in LOG_FILES: 
            if os.path.exists(f): open(f, 'w').close()
    elif action == 'clear_all_flows': 
        conn.execute("DELETE FROM flow_logs")
    elif action == 'factory_reset': 
        conn.execute("DELETE FROM flow_logs")
        conn.execute("DELETE FROM data_rates")
        conn.execute("DELETE FROM devices")
        conn.execute("DELETE FROM ips_alerts")
        conn.execute("DELETE FROM ips_rules")
        conn.execute("DELETE FROM firewall_rules")
        # Also flush iptables
        subprocess.run("sudo iptables -F", shell=True)
        subprocess.run("sudo iptables -t nat -F", shell=True)
        
    conn.commit()
    conn.close()
    return redirect(url_for('index'))

@app.route('/edit/<mac>', methods=('GET', 'POST'))
def edit(mac):
    conn = get_db()
    device = conn.execute('SELECT * FROM devices WHERE mac_addr = ?', (mac,)).fetchone()
    
    if request.method == 'POST':
        # UPDATED: Now includes ipv6_addr in the UPDATE statement
        conn.execute('''
            UPDATE devices 
            SET hostname=?, vendor=?, model=?, version=?, description=?, ipv6_addr=? 
            WHERE mac_addr=?
        ''', (
            request.form['hostname'], 
            request.form['vendor'], 
            request.form['model'], 
            request.form['version'], 
            request.form['description'],
            request.form['ipv6_addr'], # Added this field
            mac
        ))
        conn.commit()
        conn.close()
        return redirect(url_for('index'))
        
    conn.close()
    return render_template('edit.html', device=device)

@app.route('/block/<mac>')
def block(mac):
    # Insert rule at top of FORWARD chain
    subprocess.run(f"sudo iptables -I FORWARD -m mac --mac-source {mac} -j DROP", shell=True)
    return redirect(url_for('index'))

@app.route('/unblock/<mac>')
def unblock(mac):
    # Remove rule
    subprocess.run(f"sudo iptables -D FORWARD -m mac --mac-source {mac} -j DROP", shell=True)
    return redirect(url_for('index'))

@app.route('/delete_history/<mac>', methods=['POST'])
def delete_history(mac):
    conn = get_db()
    conn.execute('DELETE FROM data_rates WHERE mac_addr = ?', (mac,))
    conn.execute('DELETE FROM flow_logs WHERE mac_addr = ?', (mac,))
    conn.commit()
    conn.close()
    return redirect(url_for('device_detail', mac=mac))


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)