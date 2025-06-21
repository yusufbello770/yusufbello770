#!/usr/bin/env python3
"""
network_sniffer.py

Advanced packet sniffer with Deep Packet Inspection (DPI) capabilities
"""

import csv
import time
import platform
import json
import re
import sqlite3
from contextlib import contextmanager
from scapy.all import sniff, IP, TCP, UDP, ARP, conf, get_if_list, Raw
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet6 import IPv6
from scapy.layers.dhcp import DHCP
from scapy.layers.tls.all import TLS
from flask import Flask, render_template, jsonify, request
import threading

# Configuration
LOG_FILE = "packets_log.csv"
DB_FILE = "packets.db"
CSV_BATCH_SIZE = 100  # Number of packets to hold before writing to CSV
packet_buffer = []
is_sniffing = False
sniffing_thread = None

app = Flask(__name__)

# Database setup
@contextmanager
def get_db_connection():
    conn = sqlite3.connect(DB_FILE)
    try:
        yield conn
    finally:
        conn.close()

def init_db():
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS packets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL,
            src_ip TEXT,
            dst_ip TEXT,
            protocol TEXT,
            length INTEGER,
            src_port INTEGER,
            dst_port INTEGER,
            flags TEXT,
            dpi_data TEXT
        )
        ''')
        conn.commit()

# Packet processing functions
def extract_smtp_info(payload):
    info = {}
    lines = payload.split('\r\n')
    
    if lines and lines[0].startswith('220'):
        info["server_banner"] = lines[0][4:]
    
    commands = []
    for line in lines:
        if line.startswith(('EHLO', 'HELO', 'MAIL FROM:', 'RCPT TO:', 'DATA', 'QUIT')):
            commands.append(line)
    info["commands"] = commands
    
    return info

def extract_ftp_info(payload):
    info = {}
    lines = payload.split('\r\n')
    
    if lines and lines[0].startswith('220'):
        info["server_banner"] = lines[0][4:]
    
    commands = []
    for line in lines:
        if line.startswith(('USER', 'PASS', 'LIST', 'RETR', 'STOR')):
            commands.append(line)
    info["commands"] = commands
    
    return info

def extract_tls_info(packet):
    if packet.haslayer(TLS):
        tls = packet[TLS]
        info = {}
        
        if tls.type == 22:  # Handshake
            for msg in tls.msg:
                if msg.msgtype == 1:  # Client Hello
                    info["tls"] = {
                        "version": msg.version,
                        "ciphersuites": [cs for cs in msg.ciphers],
                        "extensions": [ext.type for ext in msg.ext]
                    }
                    for ext in msg.ext:
                        if ext.type == 0:  # server_name
                            info["tls"]["sni"] = ext.servernames[0].name.decode()
        return info
    return None

def perform_deep_inspection(packet):
    dpi_results = {}
    
    # HTTP Analysis
    if packet.haslayer(HTTP):
        if packet.haslayer(HTTPRequest):
            http = packet[HTTPRequest]
            dpi_results["http"] = {
                "method": http.Method.decode(),
                "host": http.Host.decode() if http.Host else None,
                "uri": http.Path.decode(),
                "user_agent": http.User_Agent.decode() if http.User_Agent else None
            }
        elif packet.haslayer(HTTPResponse):
            http = packet[HTTPResponse]
            dpi_results["http"] = {
                "status_code": http.Status_Code.decode(),
                "content_type": http.Content_Type.decode() if http.Content_Type else None
            }
    
    # DNS Analysis
    if packet.haslayer(DNS):
        dns = packet[DNS]
        dpi_results["dns"] = {
            "qr": "query" if dns.qr == 0 else "response",
            "questions": [q.qname.decode() for q in dns[DNSQR]] if DNSQR in dns else [],
            "answers": [{"name": r.rrname.decode(), "type": r.type, "data": r.rdata} 
                       for r in dns[DNSRR]] if DNSRR in dns else []
        }
    
    # DHCP Analysis
    if packet.haslayer(DHCP):
        dhcp = packet[DHCP]
        dpi_results["dhcp"] = {
            "options": [opt for opt in dhcp.options]
        }
    
    # TLS Analysis
    tls_info = extract_tls_info(packet)
    if tls_info:
        dpi_results.update(tls_info)
    
    # Payload Analysis
    if packet.haslayer(Raw):
        payload = packet[Raw].load
        try:
            decoded_payload = payload.decode('utf-8', errors='ignore')
            
            if "220" in decoded_payload[:100] and ("smtp" in decoded_payload.lower() or "esmtp" in decoded_payload.lower()):
                dpi_results["smtp"] = extract_smtp_info(decoded_payload)
            elif "220" in decoded_payload[:100] and "ftp" in decoded_payload[:100].lower():
                dpi_results["ftp"] = extract_ftp_info(decoded_payload)
            elif len(decoded_payload) > 10:
                dpi_results["plaintext"] = decoded_payload[:500]
    
        except UnicodeDecodeError:
            dpi_results["binary_payload"] = {
                "size": len(payload),
                "hex_sample": payload[:16].hex()
            }
    
    return dpi_results

def write_packet_to_csv(packet_info):
    with open(LOG_FILE, mode='a', newline='') as csv_file:
        fieldnames = [
            "timestamp", "src_ip", "dst_ip", "protocol", "length",
            "src_port", "dst_port", "flags", "dpi_info"
        ]
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        if csv_file.tell() == 0:
            writer.writeheader()
        writer.writerow(packet_info)

def save_packet_to_db(packet_info):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
        INSERT INTO packets (
            timestamp, src_ip, dst_ip, protocol, length,
            src_port, dst_port, flags, dpi_data
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            packet_info['timestamp'],
            packet_info['src_ip'],
            packet_info['dst_ip'],
            packet_info['protocol'],
            packet_info['length'],
            packet_info.get('src_port'),
            packet_info.get('dst_port'),
            packet_info.get('flags'),
            json.dumps(packet_info['dpi_info'])
        ))
        conn.commit()

def packet_callback(packet):
    packet_info = {
        "timestamp": time.time(),
        "src_ip": "Unknown",
        "dst_ip": "Unknown",
        "protocol": "OTHER",
        "length": len(packet),
        "dpi_info": {}
    }

    # Network Layer
    if IP in packet:
        ip_layer = packet[IP]
        packet_info.update({
            "src_ip": ip_layer.src,
            "dst_ip": ip_layer.dst,
            "ttl": ip_layer.ttl
        })
    elif IPv6 in packet:
        ip6_layer = packet[IPv6]
        packet_info.update({
            "src_ip": ip6_layer.src,
            "dst_ip": ip6_layer.dst,
            "ttl": ip6_layer.hlim
        })
    
    # Transport Layer
    if TCP in packet:
        tcp_layer = packet[TCP]
        packet_info.update({
            "protocol": "TCP",
            "src_port": tcp_layer.sport,
            "dst_port": tcp_layer.dport,
            "flags": str(tcp_layer.flags)
        })
    elif UDP in packet:
        udp_layer = packet[UDP]
        packet_info.update({
            "protocol": "UDP",
            "src_port": udp_layer.sport,
            "dst_port": udp_layer.dport
        })
    elif ARP in packet:
        packet_info.update({
            "protocol": "ARP",
            "src_ip": packet[ARP].psrc,
            "dst_ip": packet[ARP].pdst
        })
    
    # Deep Packet Inspection
    packet_info["dpi_info"] = perform_deep_inspection(packet)
    
    # Save to both CSV and database
    packet_buffer.append(packet_info)
    if len(packet_buffer) >= CSV_BATCH_SIZE:
        for pkt in packet_buffer:
            write_packet_to_csv(pkt)
            save_packet_to_db(pkt)
        packet_buffer.clear()

# Interface management
def validate_interface(interface):
    available_interfaces = get_if_list()
    if not available_interfaces:
        return None
    
    if interface is None:
        try:
            return conf.iface if hasattr(conf.iface, 'name') else conf.iface
        except:
            return available_interfaces[0]
    
    if interface in available_interfaces:
        return interface
    
    for iface in available_interfaces:
        if interface.lower() in iface.lower():
            return iface
    
    return available_interfaces[0]

def start_sniffing(interface=None, filter=""):
    valid_interface = validate_interface(interface)
    print(f"Starting packet capture on interface: {valid_interface}")
    
    if platform.system() == "Windows":
        try:
            from scapy.arch.windows import npcap
            conf.use_pcap = True
        except ImportError:
            print("Warning: Npcap not installed. Falling back to WinPcap.")
    
    try:
        sniff(iface=valid_interface, prn=packet_callback, filter=filter, store=False)
    except Exception as e:
        print(f"Error while sniffing: {str(e)}")
        if valid_interface != conf.iface:
            print(f"Falling back to default interface: {conf.iface}")
            try:
                sniff(iface=conf.iface, prn=packet_callback, store=False)
            except Exception as e:
                print(f"Error with default interface: {str(e)}")

# Web Interface
@app.route('/')
def index():
    interfaces = get_network_interfaces()
    return render_template('index.html', interfaces=interfaces)

@app.route('/start_sniffing', methods=['POST'])
def start_sniffing_route():
    global sniffing_thread, is_sniffing
    
    if is_sniffing:
        return jsonify({'status': 'error', 'message': 'Already sniffing'})
    
    interface = request.form.get('interface')
    filter = request.form.get('filter', '')
    
    is_sniffing = True
    
    def sniffing_task():
        try:
            start_sniffing(interface, filter)
        except Exception as e:
            print(f"Error in sniffing: {str(e)}")
        finally:
            global is_sniffing
            is_sniffing = False
    
    sniffing_thread = threading.Thread(target=sniffing_task)
    sniffing_thread.daemon = True
    sniffing_thread.start()
    
    return jsonify({'status': 'success', 'message': f'Started sniffing on {interface}'})

@app.route('/stop_sniffing', methods=['POST'])
def stop_sniffing():
    global is_sniffing
    if not is_sniffing:
        return jsonify({'status': 'error', 'message': 'Not sniffing'})
    
    # Scapy doesn't have a built-in way to stop sniffing, so we set a flag
    is_sniffing = False
    return jsonify({'status': 'success', 'message': 'Sniffing will stop after current packet'})

@app.route('/capture')
def capture():
    packets = []
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM packets ORDER BY timestamp DESC LIMIT 100')
            columns = [column[0] for column in cursor.description]
            packets = [dict(zip(columns, row)) for row in cursor.fetchall()]
    except Exception as e:
        print(f"Error reading from database: {e}")
    
    return render_template('capture.html', packets=packets)

def get_network_interfaces():
    interfaces = []
    ifaces = get_if_list()
    
    for iface in ifaces:
        try:
            ip = get_if_addr(iface)
            if ip and ip != "127.0.0.1":
                clean_name = iface
                if "DeviceNPF_" in iface:
                    clean_name = iface.replace("DeviceNPF_", "").replace("{", "").replace("}", "")
                
                interfaces.append({
                    'name': iface,
                    'display_name': clean_name,
                    'ip': ip
                })
        except:
            continue
    
    if not interfaces:
        interfaces.append({
            'name': conf.iface.name if hasattr(conf.iface, 'name') else conf.iface,
            'display_name': 'Default Interface',
            'ip': get_if_addr(conf.iface)
        })
    
    return interfaces

if __name__ == '__main__':
    init_db()
    
    # Check for root/admin privileges
    if platform.system() != "Windows" and os.geteuid() != 0:
        print("Error: This script must be run as root/admin.")
        exit(1)
    
    app.run(debug=True, host='0.0.0.0')