import sqlite3
import subprocess
import os

DB_PATH = 'ips_data.db'

def clear_screen():
    os.system('clear')

def get_devices():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT mac_addr, ip_addr, vendor, hostname FROM devices")
    devices = cursor.fetchall()
    conn.close()
    return devices

def block_device(mac):
    print(f"[*] Blocking {mac}...")
    # Add rule to drop packets from this MAC trying to pass through the router
    cmd = f"sudo iptables -I FORWARD -m mac --mac-source {mac} -j DROP"
    subprocess.run(cmd, shell=True)
    print(f"[!] {mac} has been BLOCKED from the internet.")

def unblock_device(mac):
    print(f"[*] Unblocking {mac}...")
    # Delete the DROP rule
    cmd = f"sudo iptables -D FORWARD -m mac --mac-source {mac} -j DROP"
    subprocess.run(cmd, shell=True)
    print(f"[+] {mac} access RESTORED.")

def show_menu():
    while True:
        clear_screen()
        print("=== SMART IPS FIREWALL CONTROL ===")
        print("ID | IP Address      | MAC Address       | Vendor")
        print("-" * 60)
        
        devices = get_devices()
        for idx, dev in enumerate(devices):
            # dev[0]=mac, dev[1]=ip, dev[2]=vendor
            print(f"{idx+1}  | {dev[1]:<15} | {dev[0]:<17} | {dev[2]}")
        
        print("-" * 60)
        print("\n[B] Block a Device")
        print("[U] Unblock a Device")
        print("[Q] Quit")
        
        choice = input("\nSelection: ").lower()
        
        if choice == 'q':
            break
        elif choice in ['b', 'u']:
            try:
                dev_id = int(input("Enter Device ID number: ")) - 1
                if 0 <= dev_id < len(devices):
                    target_mac = devices[dev_id][0]
                    if choice == 'b':
                        block_device(target_mac)
                    else:
                        unblock_device(target_mac)
                    input("\nPress Enter to continue...")
                else:
                    print("Invalid ID.")
                    input()
            except ValueError:
                print("Please enter a number.")
                input()

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[-] This script requires root. Run with sudo.")
    else:
        show_menu()