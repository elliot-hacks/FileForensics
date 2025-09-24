# 🛡️ Django Malware & Network Analysis Platform

A comprehensive **Django-based security analysis platform** that combines **malware detection, file forensics, steganography analysis, and network packet monitoring** into a single web application.  

This project integrates **YARA scanning**, **file type detection**, **image plane/steganography visualization**, **network packet sniffing**, and **statistical reporting** with a web-based interface for security researchers, analysts, and administrators.

---

## 🚀 Features

### 🔑 Authentication & User Management
- User registration and login system.
- Role-based redirects (`admin` users → Django Admin, regular users → file dashboard).
- Secure password handling via Django’s authentication system.

### 🐍 Malware & File Analysis
- Upload suspicious files for automated analysis.
- **File type detection** using [`python-magic`](https://github.com/ahupp/python-magic).
- **YARA-based malware scanning** with configurable signatures.
- Generate structured **PDF reports** of file analysis.
- Maintain a searchable & filterable database of uploaded files.

### 🖼️ Image Steganography Analysis
- Upload JPEG/PNG images.
- Extract **bit planes (0–7)** from **RGB channels**.
- Display hidden patterns that may contain steganographic content.

### 🌐 Network Packet Capture
- Select network interface for monitoring.
- **ARP packet sniffing** using [Scapy](https://scapy.net/).
- Real-time storage of device info (IP, MAC, Hostname) in the database.
- Generate `.pcap` files for offline analysis.

### 📊 Reporting & Statistics
- **Pie chart**: File uploads per user.
- **Bar chart**: Daily uploads over time.
- Visualization generated using **Matplotlib** and embedded as Base64 images.
- Exportable PDF reports.

### 🔔 Real-Time Notifications
- WebSocket-based live notifications (Django Channels).
- Device discovery alerts when new ARP packets are detected.

---

## 📂 Project Structure

```bash
├── home/               # Main app for malware/file analysis
│   ├── views.py        # Core logic (malware, network, images, reports)
│   ├── models.py       # Malware, UploadedFile, Packet models
│   ├── forms.py        # File, Image, User registration forms
│   └── templates/      # HTML templates for web UI
├── templates/          # Authentication, file listings, statistics, etc.

```
---

## ⚙️ Installation
```bash

git clone https://github.com/elliot-hacks/FileForensics.git
cd FileForensics
```

## 2️⃣ Create a Virtual Environment
```bash


python3 -m venv venv
source venv/bin/activate
```

## 3️⃣ Install Dependencies
```bash


pip install -r requirements.txt
```
---
### Key Dependencies:

```
Django

django-channels

python-magic

yara-python

scapy

Pillow

matplotlib

reportlab

plotly

```
---

## 4️⃣ Run Migrations
```bash

python manage.py migrate

```

## 5️⃣ Create a Superuser
```bash


python manage.py createsuperuser
```

## 6️⃣ Start Development Server
```bash


python manage.py runserver
```

### Access the platform at: http://localhost:8000

### 🧪 Usage
~~~
File Analysis
Login to the platform.

Upload a file for inspection.

View analysis results, detected signatures, and generate a PDF report.
~~~
### Image Steganography
~~~
Upload an image.

View extracted bit planes for RGB channels.

Detect anomalies or hidden data.

~~~

### Network Capture
~~~
Select an interface (e.g., eth0, wlan0).

Start ARP packet sniffing.

View discovered devices in the dashboard.
~~~

### Statistics
---

Navigate to the Statistics page to view:

File uploads by user.

Daily upload trends.
---

## 📊 Example Reports
---
### Malware Report (PDF)

- Filename

- Uploaded By

- File Type

- Detected Signatures

### Visualization Charts

- Pie chart (uploads per user)

- Bar chart (uploads per day)
---

## 🛡️ Security Notes
---
Root password validation for privileged operations uses sudo. Use with caution.

Ensure YARA rules are well-maintained (home/YARA/index.yar).

Run in a controlled environment (sandbox/VM) when testing unknown files.
---
## 🛠️ Roadmap
---
 Real-time dashboard for network devices.

 Extended protocol analysis beyond ARP.

 Integration with external threat intelligence APIs.

 Enhanced steganography detection (LSB algorithms).

 Docker deployment support.
---
## 🤝 Contributing
---
Pull requests are welcome! Please open an issue first to discuss proposed changes.

---
