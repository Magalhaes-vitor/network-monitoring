# Network Monitoring Tool

## Overview

This Python script provides network monitoring and security management functionalities. It monitors MAC addresses, checks the operating system version, captures network packets, and sends email notifications for various events.

## Table of Contents

- [Requirements](#requirements)
- [Setup](#setup)
- [Functions](#functions)
- [Unit Tests](#unit-tests)
- [Examples of Expected Outputs](#examples-of-expected-outputs)
- [Usage](#usage)
- [How to Create an App Password in Google](#how-to-create-an-app-password-in-google)
- [Notes](#notes)

## Requirements

- Python 3.x
- Required libraries:
  - `csv`
  - `os`
  - `subprocess`
  - `smtplib`
  - `socket`
  - `psutil`
  - `hashlib`
  - `requests`
  - `scapy`
  - `win32com.client`
  - `watchdog`

Install required libraries using:

```bash
pip install scapy watchdog requests
```

## Setup

1. Configure email settings in the script:
   ```python
   EMAIL_SENDER = 'youremail@domain.com'
   EMAIL_RECEIVER = 'recipient@domain.com'
   EMAIL_PASSWORD = 'your_password'
   SMTP_SERVER = 'smtp.domain.com'
   SMTP_PORT = 587
   ```
2. Create an `employees.csv` file with a column named `MAC Address`.

## Functions

### 1. `send_email(subject, body)`

Sends an email with the specified subject and body.

### 2. `disconnect_invalid_machines()`

Disconnects machines with MAC addresses listed in `employees.csv`.

### 3. `validate_mac_addresses()`

Validates MAC addresses on the network against those in `employees.csv`.

### 4. `get_ip_from_mac(mac_address)`

Returns the IP address associated with a given MAC address.

### 5. `monitor_new_users()`

Monitors Active Directory for new user creation.

### 6. `capture_packets()`

Captures network packets and detects login activities.

### 7. `check_os_version()`

Checks and prints the operating system version.

### 8. `monitor_file_integrity(directory)`

Monitors a directory for file modifications.

### 9. `download_and_hash_file(url, file_path)`

Downloads a file from a URL and computes its SHA256 hash.

### 10. `monitor_and_alert(directory)`

Monitors a directory and sends alerts for newly created files.

### 11. `calculate_remote_checksum(file_url)`

Calculates the SHA256 checksum of a remote file.

### 12. `main()`

The main function that orchestrates all tasks.

## Unit Tests

Here's an example of how to write unit tests for the functions in this script:

```python
import unittest
from unittest.mock import patch, MagicMock
import subprocess

class TestNetworkMonitoringTool(unittest.TestCase):

    @patch('builtins.print')
    @patch('builtins.open', new_callable=MagicMock)
    def test_disconnect_invalid_machines(self, mock_open, mock_print):
        mock_open.return_value.__enter__.return_value = [
            {'MAC Address': '00:11:22:33:44:55'},
            {'MAC Address': '66:77:88:99:AA:BB'}
        ]
        from your_script import disconnect_invalid_machines
        result = disconnect_invalid_machines()
        self.assertEqual(result, ['00:11:22:33:44:55', '66:77:88:99:AA:BB'])

    @patch('your_script.subprocess.check_output')
    def test_get_ip_from_mac(self, mock_check_output):
        mock_check_output.return_value = b'Interface: 192.168.1.1 --- 0x1\n  Internet Address      Physical Address      Type\n  192.168.1.2           00-11-22-33-44-55     dynamic\n'
        from your_script import get_ip_from_mac
        ip = get_ip_from_mac('00-11-22-33-44-55')
        self.assertEqual(ip, '192.168.1.2')

    @patch('your_script.smtplib.SMTP')
    def test_send_email(self, mock_smtp):
        from your_script import send_email
        send_email("Test Subject", "Test Body")
        mock_smtp.assert_called_once()

if __name__ == '__main__':
    unittest.main()
```

## Examples of Expected Outputs

### 1. Disconnect Invalid Machines

**Log Output:**

```
Disconnecting machine with MAC: 00:11:22:33:44:55
Disconnecting machine with MAC: 66:77:88:99:AA:BB
```

**Email Output:**

**Subject:** Suspicious Machine on the Network
**Body:**

```
Disconnected machines:
00:11:22:33:44:55
66:77:88:99:AA:BB
```

### 2. Get IP Associated with MAC Address

**Log Output:**

```
IP associated with MAC 00:11:22:33:44:55: 192.168.1.2
```

### 3. File Modification Detection

**Log Output:**

```
File modified: C:/path/to/monitor/modified_file.txt
```

### 4. Email Notification for New File Creation

**Email Output:**

**Subject:** New File Detected
**Body:**

```
New file created: C:/path/to/alert/new_file.txt
```

### 5. SHA256 Checksum Calculation

**Log Output:**

```
SHA256 checksum for file.exe: abcdef1234567890...
```

### 6. Check Operating System Version

**Log Output:**

```
Operating system version:
OS Name: Windows 10 Pro
OS Version: 10.0.19041 N/A Build 19041
```

## Usage

To execute the script, run:

```bash
python Network_Monitoring.py
```

## How to Create an App Password in Google

Follow these steps to create an app password for your Google account (necessary if using Gmail):

### Step-by-Step Guide

1. **Access Your Google Account**:

   - Go to [myaccount.google.com](https://myaccount.google.com/) and log in to your Google account.
2. **Navigate to Security**:

   - In the left panel, click on **"Security"**.
3. **Enable Two-Step Verification**:

   - Scroll down to the **"How you sign in to Google"** section.
   - If two-step verification is not enabled, click on **"2-Step Verification"** and follow the instructions to set it up.
4. **Access App Passwords**:

   - After enabling two-step verification, you will see a new section called **"App passwords"**. Click on it.
5. **Select an App and Device**:

   - On the app passwords page, you will see a dropdown menu. Select the app (e.g., "Mail") and the device (e.g., "Windows Computer") for which you want to generate the password.
6. **Generate Password**:

   - Click on **"Generate"**. Google will create a 16-character password.
7. **Note the Password**:

   - The generated password will appear in a box. Copy and save this password, as you will need it to set up the app.
8. **Use the App Password**:

   - When prompted to enter your password in an app that does not support two-step verification, use the app password you generated.
9. **Finish**:

   - After using the app password, you can close the app passwords window. If you need to generate more passwords in the future, simply repeat the steps above.

## Notes

- **Security**: App passwords are specific to the app and cannot be used to sign in to your Google account in a browser.
- **Revoke Passwords**: If you no longer need an app password, you can revoke it in the same app passwords section.

By following these steps, you can easily set up an app password to access services that do not support two-step verification!
