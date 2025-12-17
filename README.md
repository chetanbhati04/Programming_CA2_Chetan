# 🛡️ Cyber Forensics Evidence Management System

A secure web-based system for uploading, scanning, sanitizing, and extracting data from digital evidence files such as **PDFs, Excel files, and Images**.  
Built using **Django** with strong security controls suitable for **cybersecurity and digital forensics workflows**.

---

## 📌 Project Overview

Digital evidence often comes from unknown or untrusted sources. This system ensures that uploaded files are:

- ✅ Validated
- 🦠 Scanned for malware
- 🧹 Sanitized
- 📊 Automatically processed and extracted
- 📝 Fully audited

The application reduces manual work, improves accuracy, and enhances security for investigators.

---

## 🚀 Key Features

- 🔐 User Authentication (Login & Registration)
- 📁 Upload support for **PDF, Excel, and Image** files
- 🦠 Malware scanning using **ClamAV**
- 🧹 File sanitization (PDF & Image)
- 📊 Automated data extraction
- 🧾 Secure audit logging of all actions
- 🔁 Undo upload (delete file & extracted data)
- 🔗 REST API for programmatic uploads
- 🔑 JWT-based API authentication

---

## 🏗️ Technology Stack

### Backend
- Django
- Django REST Framework
- SQLite
- Simple JWT

### Frontend
- HTML5
- Bootstrap 5
- JavaScript

### Security & Processing
- ClamAV
- PyPDF2
- Pillow
- Pandas
- OpenPyXL
- Hashlib (SHA-256)

---

## 📂 Project Structure

CJ Project/
│
├── scrap_project/              # Django project settings
│   ├── settings.py
│   ├── urls.py
│   └── wsgi.py
│
├── data_capture/               # Core application logic
│   ├── models.py               # DataSource, ExtractedData, AuditLog
│   ├── views.py                # Web views & API endpoints
│   ├── security.py             # Malware scan, sanitization, audit logging
│   ├── utils.py                # Data extraction logic (PDF, Excel, Image)
│   ├── forms.py
│   └── migrations/
│
├── templates/                  # HTML templates (UI)
│   ├── authentication/
│   ├── data_capture/
│   └── base.html
│
├── media/
│   └── uploads/                # Uploaded & sanitized files
│
├── venv/                       # Python virtual environment
│
├── manage.py                   # Django management script
├── requirements.txt            # Project dependencies
└── README.md                   # Project documentation

