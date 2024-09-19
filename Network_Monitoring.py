import csv
import os
import subprocess
import smtplib
import socket
import psutil
import hashlib
import requests
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from scapy.all import sniff, ARP
from win32com.client import GetObject  # For Active Directory
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Email configurations
EMAIL_SENDER = 'youremail@domain.com'
EMAIL_RECEIVER = 'recipient@domain.com'
EMAIL_PASSWORD = 'your_password'
SMTP_SERVER = 'smtp.domain.com'
SMTP_PORT = 587

# Function to send email
def send_email(subject, body):
    msg = MIMEMultipart()
    msg['From'] = EMAIL_SENDER
    msg['To'] = EMAIL_RECEIVER
    msg['Subject'] = subject

    msg.attach(MIMEText(body, 'plain'))
    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
        server.starttls()
        server.login(EMAIL_SENDER, EMAIL_PASSWORD)
        server.sendmail(EMAIL_SENDER, EMAIL_RECEIVER, msg.as_string())

# Function to disconnect invalid machines from the network
def disconnect_invalid_machines():
    disconnected_machines = []
    with open('employees.csv', 'r') as file:
        reader = csv.DictReader(file)
        for row in reader:
            mac_address = row['MAC Address']
            # Simulate disconnection
            print(f"Disconnecting machine with MAC: {mac_address}")
            disconnected_machines.append(mac_address)  # Add to disconnection log
    return disconnected_machines

# Function to obtain MAC addresses and check if they are in the CSV
def validate_mac_addresses():
    with open('employees.csv', 'r') as file:
        reader = csv.DictReader(file)
        valid_macs = {row['MAC Address'] for row in reader}

    # Check MAC addresses on the network (using ARP)
    def arp_display(packet):
        if packet.haslayer(ARP):
            mac = packet[ARP].hwsrc
            if mac not in valid_macs:
                print(f"Invalid MAC Address detected: {mac}")

    sniff(prn=arp_display, filter='arp', store=0)

# Function to get IP associated with a MAC address
def get_ip_from_mac(mac_address):
    arp_output = subprocess.check_output(['arp', '-a']).decode()
    for line in arp_output.splitlines():
        if mac_address.lower() in line.lower():
            ip = line.split()[0]
            print(f"IP associated with MAC {mac_address}: {ip}")
            return ip
    return None

# Function to monitor creation of new users in Active Directory
def monitor_new_users():
    # Example of how to use Active Directory with win32com
    ad = GetObject("LDAP://rootDSE")
    base_dn = ad.Get("defaultNamingContext")
    query = f"(&(objectClass=user)(objectCategory=person))"
    ldap_query = f"LDAP://{base_dn}"
    # Simulate monitoring of user creation
    print("Monitoring new users in Active Directory")

# Function to capture packets and detect logins
def capture_packets():
    def packet_callback(packet):
        if packet.haslayer('Raw'):
            payload = packet['Raw'].load.decode(errors='ignore')
            if 'login' in payload.lower():
                print(f"Login detected: {payload}")

    sniff(prn=packet_callback, store=0)

# Function to check the operating system version
def check_os_version():
    os_version = subprocess.check_output('systeminfo | findstr /B /C:"OS Name" /C:"OS Version"', shell=True).decode()
    print(f"Operating system version:\n{os_version}")

# Function to monitor file integrity
def monitor_file_integrity(directory):
    class IntegrityHandler(FileSystemEventHandler):
        def on_modified(self, event):
            if not event.is_directory:
                print(f"File modified: {event.src_path}")

    observer = Observer()
    event_handler = IntegrityHandler()
    observer.schedule(event_handler, path=directory, recursive=False)
    observer.start()

# Function to download and calculate hash of files
def download_and_hash_file(url, file_path):
    response = requests.get(url)
    with open(file_path, 'wb') as file:
        file.write(response.content)
    
    sha256_hash = hashlib.sha256()
    with open(file_path, 'rb') as file:
        for byte_block in iter(lambda: file.read(4096), b""):
            sha256_hash.update(byte_block)
    print(f"SHA256 checksum for {file_path}: {sha256_hash.hexdigest()}")

# Function to monitor directory and send alerts
def monitor_and_alert(directory):
    class AlertHandler(FileSystemEventHandler):
        def on_created(self, event):
            if not event.is_directory:
                send_email('New File Detected', f"New file created: {event.src_path}")

    observer = Observer()
    event_handler = AlertHandler()
    observer.schedule(event_handler, path=directory, recursive=False)
    observer.start()

# Function to calculate checksum of remote files
def calculate_remote_checksum(file_url):
    response = requests.get(file_url)
    checksum = hashlib.sha256(response.content).hexdigest()
    print(f"Remote checksum for {file_url}: {checksum}")

# Main function
def main():
    # Disconnect invalid machines and log disconnections
    disconnected_machines = disconnect_invalid_machines()

    # Validate and get MAC addresses
    validate_mac_addresses()

    # Get IP from MAC address
    mac_address = '00:11:22:33:44:55'  # Example MAC address
    get_ip_from_mac(mac_address)

    # Monitor new users in Active Directory
    monitor_new_users()

    # Capture network packets
    capture_packets()

    # Check operating system version
    check_os_version()

    # Monitor file integrity
    monitor_file_integrity('C:/path/to/monitor')

    # Download and calculate hash of files
    download_and_hash_file('http://example.com/file.exe', 'file.exe')

    # Monitor directory and send alerts
    monitor_and_alert('C:/path/to/alert')

    # Calculate checksum of remote files
    calculate_remote_checksum('http://example.com/remote_file.exe')

    # Send email with summary of tasks
    email_body = 'All tasks were executed successfully.'
    
    if disconnected_machines:
        # Create high-priority alert if there are disconnected machines
        subject = 'Suspicious Machine on the Network'
        email_body = f"Disconnected machines:\n" + "\n".join(disconnected_machines)
        send_email(subject, email_body)
    else:
        send_email('Summary of Executed Tasks', email_body)

if __name__ == "__main__":
    main()
