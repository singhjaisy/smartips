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
    devices_raw = conn.execute('SELECT * FROM devices').fetchall()
    conn.close()
    devices = []
    for dev in devices_raw:
        d = dict(dev)
        try: subprocess.check_output(f"sudo iptables -L FORWARD -n | grep {d['mac_addr']}", shell=True, stderr=subprocess.DEVNULL); d['is_blocked'] = True
        except: d['is_blocked'] = False
        devices.append(d)
    return render_template('index.html', devices=devices)

# --- NEW IPS ROUTES ---
@app.route('/ips')
def ips_dashboard():
    conn = get_db()
    # Get active Rules with Device Names
    rules = conn.execute('''
        SELECT r.*, d.hostname, d.ip_addr 
        FROM ips_rules r 
        JOIN devices d ON r.mac_addr = d.mac_addr
    ''').fetchall()
    
    # Get Alerts
    alerts = conn.execute('''
        SELECT a.*, d.hostname 
        FROM ips_alerts a 
        LEFT JOIN devices d ON a.mac_addr = d.mac_addr 
        ORDER BY a.timestamp DESC LIMIT 50
    ''').fetchall()
    
    # Get List of Devices for the "Add Rule" dropdown
    devices = conn.execute('SELECT mac_addr, hostname, ip_addr FROM devices').fetchall()
    conn.close()
    return render_template('ips.html', rules=rules, alerts=alerts, devices=devices)

@app.route('/ips/add', methods=['POST'])
def ips_add_rule():
    mac = request.form['mac_addr']
    r_type = request.form['rule_type']
    param = request.form['parameter']
    action_p = request.form.get('action_param', 0)
    
    conn = get_db()
    conn.execute('INSERT INTO ips_rules (mac_addr, rule_type, parameter, action_param) VALUES (?, ?, ?, ?)',
                 (mac, r_type, param, action_p))
    conn.commit()
    conn.close()
    return redirect(url_for('ips_dashboard'))

@app.route('/ips/delete/<int:id>', methods=['POST'])
def ips_delete_rule(id):
    conn = get_db()
    conn.execute('DELETE FROM ips_rules WHERE id = ?', (id,))
    conn.commit()
    conn.close()
    return redirect(url_for('ips_dashboard'))

# --- EXISTING ROUTES (Firewall, History, Device Detail, etc.) ---
@app.route('/firewall')
def firewall():
    conn = get_db()
    rules = conn.execute('SELECT * FROM firewall_rules ORDER BY created_at DESC').fetchall()
    conn.close()
    return render_template('firewall.html', rules=rules)

@app.route('/firewall/add', methods=['POST'])
def add_fw_rule():
    rule_type = request.form['rule_type']; target = request.form['target']; protocol = request.form['protocol']; desc = request.form['description']
    if rule_type == 'IP':
        subprocess.run(f"sudo iptables -I FORWARD -s {target} -j DROP", shell=True)
        subprocess.run(f"sudo iptables -I FORWARD -d {target} -j DROP", shell=True)
    elif rule_type == 'PORT':
        if protocol in ['TCP', 'ALL']: subprocess.run(f"sudo iptables -I FORWARD -p tcp --dport {target} -j DROP", shell=True)
        if protocol in ['UDP', 'ALL']: subprocess.run(f"sudo iptables -I FORWARD -p udp --dport {target} -j DROP", shell=True)
    conn = get_db(); conn.execute('INSERT INTO firewall_rules (rule_type, target, protocol, description) VALUES (?, ?, ?, ?)', (rule_type, target, protocol, desc)); conn.commit(); conn.close()
    return redirect(url_for('firewall'))

@app.route('/firewall/delete/<int:rule_id>', methods=['POST'])
def delete_fw_rule(rule_id):
    conn = get_db()
    rule = conn.execute('SELECT * FROM firewall_rules WHERE id = ?', (rule_id,)).fetchone()
    if rule:
        t = rule['target']
        if rule['rule_type'] == 'IP':
            subprocess.run(f"sudo iptables -D FORWARD -s {t} -j DROP", shell=True)
            subprocess.run(f"sudo iptables -D FORWARD -d {t} -j DROP", shell=True)
        elif rule['rule_type'] == 'PORT':
            if rule['protocol'] in ['TCP', 'ALL']: subprocess.run(f"sudo iptables -D FORWARD -p tcp --dport {t} -j DROP", shell=True)
            if rule['protocol'] in ['UDP', 'ALL']: subprocess.run(f"sudo iptables -D FORWARD -p udp --dport {t} -j DROP", shell=True)
        conn.execute('DELETE FROM firewall_rules WHERE id = ?', (rule_id,)); conn.commit()
    conn.close()
    return redirect(url_for('firewall'))

@app.route('/device/<mac>')
def device_detail(mac):
    conn = get_db()
    device = conn.execute('SELECT * FROM devices WHERE mac_addr = ?', (mac,)).fetchone()
    flows = conn.execute('SELECT * FROM flow_logs WHERE mac_addr = ? ORDER BY last_activation DESC', (mac,)).fetchall()
    conn.close()
    return render_template('device_detail.html', device=device, flows=flows)

@app.route('/api/history/<mac>')
def api_history(mac):
    conn = get_db()
    days = request.args.get('days', default=1, type=float)
    cutoff = datetime.now() - timedelta(days=days)
    rows = conn.execute('SELECT timestamp, rate_kbps FROM data_rates WHERE mac_addr = ? AND timestamp > ? ORDER BY timestamp ASC', (mac, cutoff)).fetchall()
    conn.close()
    return jsonify({'labels': [r['timestamp'][11:19] for r in rows], 'data': [r['rate_kbps'] for r in rows]})

@app.route('/admin/cleanup', methods=['POST'])
def admin_cleanup():
    action = request.form.get('action'); conn = get_db()
    if action == 'clear_sys_logs': 
        for f in LOG_FILES: open(f, 'w').close()
    elif action == 'clear_all_flows': conn.execute("DELETE FROM flow_logs")
    elif action == 'factory_reset': conn.execute("DELETE FROM flow_logs"); conn.execute("DELETE FROM data_rates"); conn.execute("DELETE FROM devices"); conn.execute("DELETE FROM ips_alerts"); conn.execute("DELETE FROM ips_rules")
    conn.commit(); conn.close()
    return redirect(url_for('index'))

@app.route('/edit/<mac>', methods=('GET', 'POST'))
def edit(mac):
    conn = get_db()
    device = conn.execute('SELECT * FROM devices WHERE mac_addr = ?', (mac,)).fetchone()
    if request.method == 'POST':
        conn.execute('UPDATE devices SET hostname=?, vendor=?, model=?, version=?, description=? WHERE mac_addr=?', (request.form['hostname'], request.form['vendor'], request.form['model'], request.form['version'], request.form['description'], mac)); conn.commit(); conn.close()
        return redirect(url_for('index'))
    conn.close(); return render_template('edit.html', device=device)

@app.route('/block/<mac>')
def block(mac):
    subprocess.run(f"sudo iptables -I FORWARD -m mac --mac-source {mac} -j DROP", shell=True)
    return redirect(url_for('index'))

@app.route('/unblock/<mac>')
def unblock(mac):
    subprocess.run(f"sudo iptables -D FORWARD -m mac --mac-source {mac} -j DROP", shell=True)
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)