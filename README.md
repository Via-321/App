# Mitigating Different Malware Attacks

A cross-platform desktop application that detects and mitigates various types of malware on user devices, including desktops, laptops, and personal computers. It leverages local antivirus engine (ClamAV) and cloud-based threat intelligence (VirusTotal API) for comprehensive protection.

---

## Features

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

## Technologies Used

- **Python** – Core application logic
- **ClamAV** – Local antivirus engine
- **VirusTotal API** – Cloud‑based threat intelligence

---

## Installation Guide

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
3. Open in VS Code (Optional)
bash
code .
4. Install Dependencies
bash
pip install -r requirements.txt
5. Install ClamAV
OS	Command / Instruction
Windows	Download from clamav.net and extract to CLAMAV folder
macOS	brew install clamav
Linux	sudo apt install clamav
6. Run the Application
bash
python app.py
Quick Start
Protection starts automatically when the app launches

By default, it monitors: Desktop, Downloads, Documents

Use Quick Scan for daily checks

Use Full Scan for cloud‑powered deep analysis

Main Features & Usage
Feature	Description
Real‑Time Protection	Automatically scans new files in key folders and USB drives in real time
Quick Scan	Scans Desktop, Downloads, Documents
Full Scan	Deep scan of a selected folder or drive with cloud enrichment
Custom Scan	Scan a single file or a specific folder
USB Scan	Targeted scan for removable drives
Folder Monitoring (Real‑Time)
Downloads

Desktop

Documents

USB Drives

