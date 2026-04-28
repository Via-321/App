# 🛡️ Malware Detection & Mitigation Tool

A cross-platform desktop application that detects and mitigates various types of malware on user devices, including desktops, laptops, and personal computers. It leverages local antivirus engine (ClamAV) and cloud-based threat intelligence (VirusTotal API) for comprehensive protection.

---

## 🚀 Features

- **Real-Time Protection** – Automatically scans new files in:
  - Downloads folder
  - Desktop folder
  - Documents folder
  - USB drives (when plugged in)

- **Multiple Scan Modes**
  - **Quick Scan** – Checks Desktop, Downloads, and Documents
  - **Full Scan** – Deep scans selected drives/folders with cloud analysis
  - **Custom Scan** – Scan a single file or specific folder
  - **USB Scan** – Targeted scan for removable drives

- **Dual‑Engine Detection**
  - Local: ClamAV
  - Cloud: VirusTotal API

---

## 🧰 Technologies Used

- **Python** – Core application logic
- **ClamAV** – Local antivirus engine
- **VirusTotal API** – Cloud‑based threat intelligence

---

## 📦 Installation Guide

### Prerequisites

- Windows / macOS / Linux
- Internet connection (required for cloud scanning)
- Python 3.7 or higher

### Step‑by‑Step Installation

#### 1. Install Python
Download and install Python from [python.org](https://python.org)

#### 2. Clone the Repository
```bash
git clone https://github.com/Via-321/App.git
cd App
