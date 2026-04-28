
This software application detects and mitigates various types of malware on user devices including desktops, laptops, and personal computers.
Technologies Used: Python, ClamAV, VirusTotal API

Installation Guide
Prerequisites
•	Windows / macOS / Linux
•	Internet connection (for cloud scanning)
Step-by-Step Installation
1. Install Python
Download and install Python from python.org
2. Clone the Repository
bash
git clone https://github.com/Via-321/App.git
cd App
3. Open in VS Code
bash
code .
4. Install Dependencies
Open terminal and run:
bash
pip install -r requirements.txt
5. Install ClamAV
OS	Command
Windows	Download from clamav.net, extract to CLAMAV folder

macOS	brew install clamav
Linux	sudo apt install clamav
6. Run the Application
bash
python app.py
Quick Start
•	Protection activates automatically on launch
•	Monitors: Desktop, Downloads, Documents
•	Use Quick Scan for daily checks
•	Use Full Scan for cloud-powered analysis






Main Features & Usage

1. Real-Time Protection
What it does:  Automatically scans new files in
•	Downloads folder
•	Desktop folder
•	Documents folder
•	USB drives (when plugged in)

2. Scanning Options

Scan Type
•	Quick Scan
•	Full Scan
•	Custom Scan
•	USB Scan
What it scans
•	Desktop, Downloads, Documents
•	Selected folder/drive
•	Single file
•	Removable drives
