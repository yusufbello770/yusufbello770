#!/usr/bin/env python3
"""
network_sniffer.py with Anomaly Detection

Advanced packet sniffer with Deep Packet Inspection (DPI) and Automatic Anomaly Detection
"""

import csv
import time
import platform
import json
import re
import sqlite3
import numpy as np
from collections import defaultdict, deque
from contextlib import contextmanager
from scapy.all import sniff, IP, TCP, UDP, ARP, conf, get_if_list, Raw, Ether
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet6 import IPv6
from scapy.layers.dhcp import DHCP
from scapy.layers.tls.all import TLS
from flask import Flask, render_template, jsonify, request
import threading
import hashlib
from datetime import datetime, timedelta

# Configuration
LOG_FILE = "packets_log.csv"
DB_FILE = "packets.db"
CSV_BATCH_SIZE = 100
ANOMALY_DB_FILE = "anomalies.db"
packet_buffer = []
is_sniffing = False
sniffing_thread = None
anomaly_detection_thread = None
detection_running = True

app = Flask(__name__)

# ======================
# ANOMALY DETECTION MODULE
# ======================

class AnomalyDetector:
    def __init__(self):
        self.window_size = 30  # seconds for sliding window
        self.packet_counts = defaultdict(lambda: deque(maxlen=1000))
        self.port_scan_threshold = 15  # ports per second
        self.syn_flood_threshold = 100  # SYN packets per second
        self.dns_amp_threshold = 50  # DNS responses per second
        self.data_exfil_threshold = 10 * 1024 * 1024  # 10 MB per minute
        self.last_anomaly_check = time.time()
        self.anomaly_check_interval = 5  # seconds
        
        # Baseline learning period (60 seconds)
        self.baseline_period = 60
        self.baseline_start = time.time()
        self.baseline_data = {
            'packet_rates': [],
            'port_activity': defaultdict(list),
            'protocol_dist': defaultdict(list)
        }
        self.baseline_established = False
        self.baselines = {}

    def update_baseline(self, packet):
        """Collect data during baseline period"""
        elapsed = time.time() - self.baseline_start
        
        # Count packet rate every second
        if elapsed > len(self.baseline_data['packet_rates']):
            self.baseline_data['packet_rates'].append(len(self.packet_counts['all']))
            
            # Reset packet count
            self.packet_counts['all'] = deque(maxlen=1000)
        
        # Record port activity
        if TCP in packet or UDP in packet:
            src_port = packet[TCP].sport if TCP in packet else packet[UDP].sport
            self.baseline_data['port_activity'][src_port].append(time.time())
        
        # Record protocol distribution
        protocol = "OTHER"
        if IP in packet:
            if TCP in packet:
                protocol = "TCP"
            elif UDP in packet:
                protocol = "UDP"
        elif ARP in packet:
            protocol = "ARP"
        self.baseline_data['protocol_dist'][protocol].append(time.time())
        
        # Check if baseline period is complete
        if elapsed >= self.baseline_period and not self.baseline_established:
            self.calculate_baselines()
            self.baseline_established = True
            print("Network baselines established")

    def calculate_baselines(self):
        """Calculate baseline metrics from collected data"""
        # Packet rate baseline (mean and std)
        rates = self.baseline_data['packet_rates']
        self.baselines['packet_rate'] = {
            'mean': np.mean(rates),
            'std': np.std(rates),
            'threshold': np.mean(rates) + 3 * np.std(rates)  # 3-sigma rule
        }
        
        # Port activity baselines
        port_activity = {}
        for port, timestamps in self.baseline_data['port_activity'].items():
            if len(timestamps) > 1:
                intervals = np.diff(sorted(timestamps))
                port_activity[port] = {
                    'mean_interval': np.mean(intervals),
                    'std_interval': np.std(intervals),
                    'count': len(timestamps)
                }
        self.baselines['port_activity'] = port_activity
        
        # Protocol distribution
        protocol_counts = {proto: len(times) for proto, times in self.baseline_data['protocol_dist'].items()}
        total = sum(protocol_counts.values())
        self.baselines['protocol_dist'] = {proto: count/total for proto, count in protocol_counts.items()}
        
        print(f"Baselines calculated: {self.baselines}")

    def detect_anomalies(self, packet):
        """Detect anomalies in real-time"""
        current_time = time.time()
        src_ip = "unknown"
        
        # Get source IP
        if IP in packet:
            src_ip = packet[IP].src
        elif ARP in packet:
            src_ip = packet[ARP].psrc
        
        # Update packet counts
        self.packet_counts['all'].append(current_time)
        self.packet_counts[src_ip].append(current_time)
        
        # Update baseline during learning period
        if not self.baseline_established:
            self.update_baseline(packet)
            return []
        
        anomalies = []
        
        # 1. Detect SYN Flood attacks
        if TCP in packet and packet[TCP].flags == 'S':  # SYN packet
            syn_count = sum(1 for t in self.packet_counts[src_ip] 
                          if current_time - t < 1 and t > current_time - 1)
            if syn_count > self.syn_flood_threshold:
                anomalies.append({
                    'type': 'SYN_Flood',
                    'source': src_ip,
                    'severity': 'critical',
                    'description': f'SYN flood detected: {syn_count} SYN packets in 1 second'
                })
        
        # 2. Detect Port Scanning
        if TCP in packet or UDP in packet:
            # Track destination ports per source IP
            port_key = f"{src_ip}_ports"
            dst_port = packet[TCP].dport if TCP in packet else packet[UDP].dport
            self.packet_counts[port_key].append((dst_port, current_time))
            
            # Count unique ports in last 5 seconds
            recent_ports = {port for port, t in self.packet_counts[port_key] 
                           if current_time - t < 5}
            if len(recent_ports) > self.port_scan_threshold:
                anomalies.append({
                    'type': 'Port_Scan',
                    'source': src_ip,
                    'severity': 'high',
                    'description': f'Port scan detected: {len(recent_ports)} unique ports in 5 seconds'
                })
        
        # 3. Detect DNS Amplification attacks
        if UDP in packet and packet[UDP].dport == 53:  # DNS Query
            dns_key = f"{src_ip}_dns"
            self.packet_counts[dns_key].append(current_time)
            
            dns_count = sum(1 for t in self.packet_counts[dns_key] 
                          if current_time - t < 1)
            if dns_count > self.dns_amp_threshold:
                anomalies.append({
                    'type': 'DNS_Amplification',
                    'source': src_ip,
                    'severity': 'high',
                    'description': f'DNS amplification attempt: {dns_count} DNS queries in 1 second'
                })
        
        # 4. Detect Data Exfiltration (large transfers)
        if len(packet) > 1500:  # Large packet
            data_key = f"{src_ip}_data"
            self.packet_counts[data_key].append(len(packet))
            
            # Calculate total data in last minute
            total_data = sum(self.packet_counts[data_key])
            if total_data > self.data_exfil_threshold:
                anomalies.append({
                    'type': 'Data_Exfiltration',
                    'source': src_ip,
                    'severity': 'medium',
                    'description': f'Large data transfer: {total_data/(1024*1024):.2f} MB in 1 minute'
                })
        
        # 5. Detect Protocol Anomalies (using baselines)
        if current_time - self.last_anomaly_check > self.anomaly_check_interval:
            self.last_anomaly_check = current_time
            
            # Check packet rate anomaly
            current_rate = len([t for t in self.packet_counts['all'] 
                              if current_time - t < 1])
            baseline = self.baselines['packet_rate']
            if current_rate > baseline['threshold']:
                anomalies.append({
                    'type': 'Traffic_Spike',
                    'source': 'network',
                    'severity': 'medium',
                    'description': f'Traffic spike: {current_rate} packets/sec (baseline: {baseline["mean"]:.1f}±{baseline["std"]:.1f})'
                })
        
        return anomalies

# ======================
# DATABASE & STORAGE
# ======================

@contextmanager
def get_db_connection(db_file=DB_FILE):
    conn = sqlite3.connect(db_file)
    try:
        yield conn
    finally:
        conn.close()

def init_db():
    # Initialize packets database
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
        # Add indexes for faster queries
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON packets(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_src_ip ON packets(src_ip)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_protocol ON packets(protocol)')
        conn.commit()
    
    # Initialize anomalies database
    with get_db_connection(ANOMALY_DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS anomalies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL,
            type TEXT,
            source TEXT,
            severity TEXT,
            description TEXT,
            packet_ids TEXT  # Comma-separated list of related packet IDs
        )
        ''')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_anomaly_type ON anomalies(type)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_anomaly_time ON anomalies(timestamp)')
        conn.commit()

def save_anomaly_to_db(anomaly, packet_ids=None):
    """Save detected anomaly to database"""
    with get_db_connection(ANOMALY_DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute('''
        INSERT INTO anomalies (
            timestamp, type, source, severity, description, packet_ids
        ) VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            time.time(),
            anomaly['type'],
            anomaly['source'],
            anomaly['severity'],
            anomaly['description'],
            ','.join(map(str, packet_ids)) if packet_ids else ''
        ))
        conn.commit()

# ======================
# PACKET PROCESSING
# ======================

# (Existing functions: extract_smtp_info, extract_ftp_info, 
#  extract_tls_info, perform_deep_inspection, write_packet_to_csv, 
#  save_packet_to_db, packet_callback)
# ... [Keep the existing packet processing functions from previous implementation] ...

# Add this to packet_callback:
def packet_callback(packet):
    # ... [Existing packet processing code] ...
    
    # After processing, add to anomaly detector
    global detector
    anomalies = detector.detect_anomalies(packet)
    
    # Save detected anomalies
    if anomalies:
        packet_id = save_packet_to_db(packet_info)  # Need to return ID from save function
        for anomaly in anomalies:
            save_anomaly_to_db(anomaly, [packet_id])

# ======================
# ANOMALY DETECTION THREAD
# ======================

def batch_anomaly_detection():
    """Periodic batch analysis of stored packets"""
    global detection_running
    while detection_running:
        time.sleep(60)  # Run every minute
        
        # Analyze traffic patterns in the last 5 minutes
        cutoff = time.time() - 300
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # 1. Detect Beaconing (periodic communication)
            cursor.execute('''
                SELECT src_ip, dst_ip, COUNT(*) as cnt, 
                       AVG(timestamp - LAG(timestamp) OVER (PARTITION BY src_ip, dst_ip ORDER BY timestamp)) as avg_interval
                FROM packets
                WHERE timestamp > ?
                GROUP BY src_ip, dst_ip
                HAVING cnt > 10 AND avg_interval BETWEEN 1 AND 300
            ''', (cutoff,))
            
            beaconing = cursor.fetchall()
            for src_ip, dst_ip, cnt, avg_int in beaconing:
                save_anomaly_to_db({
                    'type': 'Beaconing',
                    'source': src_ip,
                    'severity': 'suspicious',
                    'description': f'Periodic communication to {dst_ip}: {cnt} times, avg {avg_int:.1f}s interval'
                })
            
            # 2. Detect Protocol Violations
            cursor.execute('''
                SELECT protocol, COUNT(*) as cnt, 
                       COUNT(*) * 1.0 / (SELECT COUNT(*) FROM packets WHERE timestamp > ?) as percentage
                FROM packets
                WHERE timestamp > ?
                GROUP BY protocol
            ''', (cutoff, cutoff))
            
            protocols = cursor.fetchall()
            baseline_protocols = detector.baselines.get('protocol_dist', {})
            for protocol, cnt, percentage in protocols:
                baseline = baseline_protocols.get(protocol, 0.01)
                if percentage > baseline * 2:  # 100% increase
                    save_anomaly_to_db({
                        'type': 'Protocol_Anomaly',
                        'source': 'network',
                        'severity': 'medium',
                        'description': f'Increased {protocol} traffic: {percentage:.1%} (baseline: {baseline:.1%})'
                    })
            
            # 3. Detect Unusual Geographic Patterns (simplified)
            cursor.execute('''
                SELECT src_ip, COUNT(DISTINCT dst_ip) as cnt
                FROM packets
                WHERE timestamp > ? AND src_ip NOT LIKE '192.168.%' AND src_ip NOT LIKE '10.%'
                GROUP BY src_ip
                HAVING cnt > 20
            ''', (cutoff,))
            
            unusual_geo = cursor.fetchall()
            for src_ip, cnt in unusual_geo:
                save_anomaly_to_db({
                    'type': 'Geographic_Anomaly',
                    'source': src_ip,
                    'severity': 'suspicious',
                    'description': f'Communicating with {cnt} external hosts in 5 minutes'
                })

# ======================
# WEB INTERFACE ENHANCEMENTS
# ======================

@app.route('/anomalies')
def view_anomalies():
    """Display detected anomalies"""
    anomalies = []
    try:
        with get_db_connection(ANOMALY_DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM anomalies ORDER BY timestamp DESC LIMIT 100')
            columns = [column[0] for column in cursor.description]
            anomalies = [dict(zip(columns, row)) for row in cursor.fetchall()]
    except Exception as e:
        print(f"Error reading anomalies: {e}")
    
    return render_template('anomalies.html', anomalies=anomalies)

@app.route('/network_health')
def network_health():
    """Display network health dashboard"""
    stats = {}
    
    # Get traffic statistics
    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        # Last 5 minutes traffic
        cutoff = time.time() - 300
        cursor.execute('SELECT COUNT(*) FROM packets WHERE timestamp > ?', (cutoff,))
        stats['packet_count'] = cursor.fetchone()[0]
        
        cursor.execute('SELECT protocol, COUNT(*) FROM packets WHERE timestamp > ? GROUP BY protocol', (cutoff,))
        stats['protocols'] = dict(cursor.fetchall())
        
        cursor.execute('SELECT src_ip, COUNT(*) FROM packets WHERE timestamp > ? GROUP BY src_ip ORDER BY COUNT(*) DESC LIMIT 5', (cutoff,))
        stats['top_sources'] = cursor.fetchall()
        
        cursor.execute('SELECT dst_ip, COUNT(*) FROM packets WHERE timestamp > ? GROUP BY dst_ip ORDER BY COUNT(*) DESC LIMIT 5', (cutoff,))
        stats['top_destinations'] = cursor.fetchall()
    
    # Get anomaly statistics
    with get_db_connection(ANOMALY_DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT severity, COUNT(*) FROM anomalies WHERE timestamp > ? GROUP BY severity', (cutoff,))
        stats['anomalies'] = dict(cursor.fetchall())
    
    # Get baseline comparison
    if detector.baseline_established:
        stats['baseline'] = detector.baselines['packet_rate']
        current_rate = len([t for t in detector.packet_counts['all'] if time.time() - t < 1])
        stats['current_rate'] = current_rate
    
    return render_template('health.html', stats=stats)

# Add to existing /capture route:
@app.route('/capture')
def capture():
    # ... existing code ...
    # Add anomaly flag to packets
    for packet in packets:
        if packet['packet_ids']:
            packet['has_anomaly'] = True
        else:
            packet['has_anomaly'] = False
    
    return render_template('capture.html', packets=packets)

# ======================
# MAIN EXECUTION
# ======================

if __name__ == '__main__':
    init_db()
    detector = AnomalyDetector()
    
    # Start batch anomaly detection thread
    detection_running = True
    anomaly_detection_thread = threading.Thread(target=batch_anomaly_detection)
    anomaly_detection_thread.daemon = True
    anomaly_detection_thread.start()
    
    # Privilege check
    if platform.system() != "Windows" and os.geteuid() != 0:
        print("Error: This script must be run as root/admin.")
        exit(1)
    
    app.run(debug=True, host='0.0.0.0')