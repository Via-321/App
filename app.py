import os
import platform
import subprocess
import threading
import queue
import shutil
import time
import sys
import tempfile
import json
import requests
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import pystray
from PIL import Image, ImageDraw
import psutil

SCRIPT_DIR = os.path.abspath(os.path.dirname(__file__))
CLAMAV_PATH = os.path.join(SCRIPT_DIR, "CLAMAV")

VIRUSTOTAL_API_KEY = "cd75242113848d6c30f1ab2c5817d61fe08ce94d2d7e5f874118f1ce47cb9c5f"

def find_executable(name):
    candidate = os.path.join(CLAMAV_PATH, name)
    if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
        return candidate
    if platform.system() == "Windows":
        candidate_exe = candidate + ".exe"
        if os.path.isfile(candidate_exe) and os.access(candidate_exe, os.X_OK):
            return candidate_exe
        
    which = shutil.which(name)
    if which:
        return which
    return None

CLAMSCAN = find_executable("clamscan")
FRESHCLAM = find_executable("freshclam")

MALWARE_DATABASE = {
    "Trojan": {
        "description": "A malicious program that disguises itself as legitimate software",
        "risk_level": "High",
        "actions": ["Steal data", "Create backdoors", "Download other malware"],
        "removal": "Delete immediately and run full system scan"
    },
    "Virus": {
        "description": "Self-replicating malware that attaches to clean files",
        "risk_level": "High",
        "actions": ["Corrupt files", "Spread to other systems", "Damage system"],
        "removal": "Delete infected files and restore from backup"
    },
    "Ransomware": {
        "description": "Encrypts files and demands payment for decryption",
        "risk_level": "Critical",
        "actions": ["Encrypt files", "Display ransom note", "Block system access"],
        "removal": "Do not pay ransom, use decryption tools if available"
    },
    "Spyware": {
        "description": "Secretly monitors user activity and collects information",
        "risk_level": "Medium",
        "actions": ["Monitor keystrokes", "Capture screenshots", "Steal credentials"],
        "removal": "Delete and change all passwords"
    },
    "Adware": {
        "description": "Displays unwanted advertisements and may track browsing habits",
        "risk_level": "Low",
        "actions": ["Show pop-up ads", "Redirect browsers", "Collect browsing data"],
        "removal": "Delete and reset browser settings"
    },
    "Worm": {
        "description": "Self-replicating malware that spreads through networks",
        "risk_level": "High",
        "actions": ["Spread rapidly", "Consume bandwidth", "Carry payloads"],
        "removal": "Delete and disconnect from network"
    },
    "Rootkit": {
        "description": "Hides itself and other malware from detection",
        "risk_level": "Critical",
        "actions": ["Hide processes", "Grant remote access", "Bypass security"],
        "removal": "Use specialized rootkit removal tools"
    },
    "Backdoor": {
        "description": "Provides unauthorized remote access to the system",
        "risk_level": "High",
        "actions": ["Allow remote control", "Bypass authentication", "Install more malware"],
        "removal": "Delete and change all access credentials"
    },
    "Keylogger": {
        "description": "Records keystrokes to steal passwords and sensitive data",
        "risk_level": "High",
        "actions": ["Record typing", "Capture passwords", "Steal personal data"],
        "removal": "Delete and change all passwords immediately"
    }
}

class BackgroundService:
    """Background service manager for system tray operation"""
    
    def __init__(self, scanner_app):
        self.scanner_app = scanner_app
        self.tray_icon = None
        self.is_running = False
        
    def create_tray_icon(self):
        """Create system tray icon"""
        # Create a simple shield icon
        image = Image.new('RGB', (64, 64), color='#0f172a')
        dc = ImageDraw.Draw(image)
        dc.rectangle([16, 16, 48, 48], fill='#3b82f6', outline='#ffffff', width=2)
        dc.rectangle([20, 20, 44, 44], fill='#1e40af')
        
        menu = pystray.Menu(
            pystray.MenuItem("Show CyberCorp", self.show_app),
            pystray.MenuItem("Quick Scan", self.quick_scan),
            pystray.MenuItem("---", None),
            pystray.MenuItem("Protection: Active" if self.scanner_app.protection_active else "Protection: Inactive", None),
            pystray.MenuItem("---", None),
            pystray.MenuItem("Exit", self.exit_app)
        )
        
        self.tray_icon = pystray.Icon("cybercorp", image, "CyberCorp Security", menu)
        self.is_running = True
        
    def show_app(self, icon=None, item=None):
        """Show the main application window"""
        if self.scanner_app.root.winfo_exists():
            self.scanner_app.root.deiconify()
            self.scanner_app.root.attributes('-topmost', True)
            self.scanner_app.root.attributes('-topmost', False)
            self.scanner_app.root.lift()
            self.scanner_app.root.focus_force()
        
    def quick_scan(self, icon=None, item=None):
        """Start quick scan from tray"""
        if self.scanner_app.root.winfo_exists():
            self.scanner_app.quick_scan()
        
    def exit_app(self, icon=None, item=None):
        """Exit application completely"""
        self.is_running = False
        if self.tray_icon:
            self.tray_icon.stop()
        
        # Stop protection and quit
        if hasattr(self.scanner_app, 'stop_realtime_protection'):
            self.scanner_app.stop_realtime_protection()
            
        if self.scanner_app.root.winfo_exists():
            self.scanner_app.root.quit()
            self.scanner_app.root.destroy()
        
    def run_in_background(self):
        """Run application in background (system tray)"""
        if self.scanner_app.root.winfo_exists():
            self.scanner_app.root.withdraw()
        
        if not self.tray_icon:
            self.create_tray_icon()
            
        # Start tray icon in separate thread to avoid blocking
        def run_tray():
            try:
                self.tray_icon.run()
            except Exception as e:
                print(f"Tray error: {e}")
                
        tray_thread = threading.Thread(target=run_tray, daemon=True)
        tray_thread.start()

class VirusTotalScanner:
    """VirusTotal API integration for file scanning"""
    
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"
        self.is_scanning = False
        
    def scan_file(self, file_path, progress_callback=None):
        """Scan a file progress updates"""
        try:
            if not self.api_key:
                return {"error": "There's something went wrong. Please try againn later."}
                
            # Get file size first
            file_size = os.path.getsize(file_path)
            if file_size > 32000000:  # 32MB limit
                return {"error": "File size exceeds limit (32MB)"}
            
            self.is_scanning = True
            
            # Upload file for scanning
            if progress_callback:
                progress_callback("Uploading file...")
                
            upload_url = f"{self.base_url}/files"
            headers = {"x-apikey": self.api_key}
            
            with open(file_path, 'rb') as file:
                files = {'file': (os.path.basename(file_path), file)}
                response = requests.post(upload_url, headers=headers, files=files, timeout=60)
            
            if response.status_code == 200:
                result = response.json()
                analysis_id = result['data']['id']
                
                if progress_callback:
                    progress_callback("File uploaded. Waiting for analysis...")
                
                # Wait for analysis to complete with longer timeout
                analysis_result = self._get_analysis_result(analysis_id, progress_callback)
                return analysis_result
            else:
                error_msg = f"Upload failed: {response.status_code}"
                if response.status_code == 401:
                    error_msg += " - Invalid API key"
                elif response.status_code == 429:
                    error_msg += " - API rate limit exceeded"
                elif response.status_code == 403:
                    error_msg += " - Access forbidden"
                return {"error": error_msg}
                
        except requests.exceptions.Timeout:
            return {"error": "Request timeout - server is not responding"}
        except requests.exceptions.ConnectionError:
            return {"error": "Network connection error - check your internet connection"}
        except Exception as e:
            return {"error": f"Scan failed: {str(e)}"}
        finally:
            self.is_scanning = False
    
    def _get_analysis_result(self, analysis_id, progress_callback=None, max_attempts=15):
        """Get analysis result with polling and progress updates"""
        analysis_url = f"{self.base_url}/analyses/{analysis_id}"
        headers = {"x-apikey": self.api_key}
        
        for attempt in range(max_attempts):
            if not self.is_scanning:
                return {"error": "Scan cancelled."}
                
            time.sleep(10)
            
            if progress_callback:
                progress_callback(f"Analyzing... ({attempt + 1}/{max_attempts})")
            
            try:
                response = requests.get(analysis_url, headers=headers, timeout=30)
                
                if response.status_code == 200:
                    result = response.json()
                    status = result['data']['attributes']['status']
                    
                    if status == 'completed':
                        if progress_callback:
                            progress_callback("Analysis complete!")
                        return self._parse_analysis_result(result)
                    elif status == 'queued':
                        continue
                    else:
                        return {"error": f"Analysis status: {status}"}
                else:
                    return {"error": f"Analysis check failed: {response.status_code}"}
                    
            except requests.exceptions.Timeout:
                if attempt == max_attempts - 1:  # Last attempt
                    return {"error": "Analysis timeout - Servers are busy"}
                continue
            except Exception as e:
                return {"error": f"Analysis check error: {str(e)}"}
        
        return {"error": "Analysis timeout - maximum attempts reached"}
    
    def _parse_analysis_result(self, result):
        """Parse analysis result"""
        attributes = result['data']['attributes']
        stats = attributes.get('stats', {})
        
        return {
            'malicious': stats.get('malicious', 0),
            'suspicious': stats.get('suspicious', 0),
            'undetected': stats.get('undetected', 0),
            'harmless': stats.get('harmless', 0),
            'total_engines': sum(stats.values()),
            'results': attributes.get('results', {}),
            'status': 'completed',
            'scan_date': attributes.get('date', '')
        }
    
    def stop_scan(self):
        """Stop the current scan"""
        self.is_scanning = False

class ProfessionalNotification:
    """Professional security notification system"""
    def __init__(self, gui_app):
        self.gui_app = gui_app
        self.notification_window = None
        
    def show_notification(self, title, message, notification_type="info", duration=5000):
        """Show professional security notification"""
        # If app is minimized to tray, use system notification
        if hasattr(self.gui_app, 'background_service') and self.gui_app.background_service.is_running:
            if self.gui_app.root.state() == 'withdrawn':
                self._show_system_notification(title, message, notification_type)
                return
        
        # Show custom notification
        notif = tk.Toplevel(self.gui_app.root)
        notif.title("Security Notification")
        notif.overrideredirect(True)
        notif.attributes('-topmost', True)
        notif.attributes('-alpha', 0.0)
        
        # Color scheme based on notification type
        colors = {
            "info": {"bg": "#1e3a5f", "accent": "#3b82f6"},
            "warning": {"bg": "#7c2d12", "accent": "#f59e0b"},
            "danger": {"bg": "#7f1d1d", "accent": "#ef4444"},
            "success": {"bg": "#065f46", "accent": "#10b981"}
        }
        color = colors.get(notification_type, colors["info"])
        
        notif.configure(bg=color["bg"])
        
        # Calculate position (bottom-right)
        screen_width = notif.winfo_screenwidth()
        screen_height = notif.winfo_screenheight()
        window_width = 350
        window_height = 120
        x = screen_width - window_width - 20
        y = screen_height - window_height - 50
        
        notif.geometry(f'{window_width}x{window_height}+{x}+{y}')
        
        # Main content frame
        main_frame = tk.Frame(notif, bg=color["bg"], padx=15, pady=12)
        main_frame.pack(fill='both', expand=True)
        
        # Header with icon and title
        header_frame = tk.Frame(main_frame, bg=color["bg"])
        header_frame.pack(fill='x')
        
        # Notification icon
        icon_text = "🛡️" if notification_type == "info" else "⚠️" if notification_type == "warning" else "🚨" if notification_type == "danger" else "✅"
        icon_label = tk.Label(header_frame, text=icon_text, font=('Arial', 14), 
                             fg=color["accent"], bg=color["bg"])
        icon_label.pack(side='left')
        
        # Title
        title_label = tk.Label(header_frame, text=title, font=('Arial', 11, 'bold'), 
                              fg='white', bg=color["bg"], anchor='w')
        title_label.pack(side='left', padx=(8, 0), fill='x', expand=True)
        
        # Close button
        close_btn = tk.Label(header_frame, text="✕", font=('Arial', 10), 
                            fg='#94a3b8', bg=color["bg"], cursor='hand2')
        close_btn.pack(side='right')
        close_btn.bind('<Button-1>', lambda e: notif.destroy())
        
        # Message
        message_label = tk.Label(main_frame, text=message, font=('Arial', 9), 
                                fg='#e2e8f0', bg=color["bg"], anchor='w', justify='left')
        message_label.pack(fill='x', pady=(8, 0))
        
        # Progress bar for scanning notifications
        if "Scanning" in title:
            progress_frame = tk.Frame(main_frame, bg=color["bg"])
            progress_frame.pack(fill='x', pady=(10, 0))
            progress = ttk.Progressbar(progress_frame, mode='indeterminate', length=320)
            progress.pack(fill='x')
            progress.start()
        
        # Add border
        notif.configure(highlightbackground=color["accent"], highlightthickness=1)
        
        # Animations
        def fade_in():
            for i in range(0, 101, 15):
                notif.attributes('-alpha', i/100)
                notif.update()
                time.sleep(0.02)
        
        def auto_close():
            time.sleep(duration/1000)
            if notif.winfo_exists():
                for i in range(100, -1, -15):
                    if notif.winfo_exists():
                        notif.attributes('-alpha', i/100)
                        notif.update()
                        time.sleep(0.02)
                notif.destroy()
        
        # Bind click to close
        for widget in [notif, main_frame, header_frame, message_label]:
            widget.bind('<Button-1>', lambda e: notif.destroy())
        
        # Start animations
        threading.Thread(target=fade_in, daemon=True).start()
        threading.Thread(target=auto_close, daemon=True).start()
        
        self.notification_window = notif
        return notif

    def _show_system_notification(self, title, message, notification_type):
        """Show system notification when app is in tray"""
        try:
            if platform.system() == "Windows":
                # Windows toast notification
                from win10toast import ToastNotifier
                toaster = ToastNotifier()
                toaster.show_toast(
                    title,
                    message,
                    duration=5,
                    threaded=True
                )
            else:
                # macOS and Linux notification
                import subprocess
                if platform.system() == "Darwin":  # macOS
                    subprocess.run(['osascript', '-e', f'display notification "{message}" with title "{title}"'])
                else:  # Linux
                    subprocess.run(['notify-send', title, message])
        except Exception:
            # Fallback to console output
            print(f"NOTIFICATION: {title} - {message}")

class USBNotifier:
    def __init__(self, gui_app):
        self.gui_app = gui_app
        self.last_drives = set()
        self.running = True
        self.monitor_thread = threading.Thread(target=self._monitor_usb, daemon=True)
        self.monitor_thread.start()
        
    def _monitor_usb(self):
        """Monitor for USB drive insertion"""
        while self.running:
            try:
                current_drives = set(detect_removable_drives())
                new_drives = current_drives - self.last_drives
                
                for drive in new_drives:
                    if drive:
                        self.gui_app.queue.put((self.gui_app._notify_usb_detected, (drive,)))
                
                self.last_drives = current_drives
                time.sleep(2)
                
            except Exception as e:
                self.gui_app.queue.put((self.gui_app._log_error, (f"US error: {e}",)))
                time.sleep(5)
    
    def stop(self):
        self.running = False

class DownloadScanner(FileSystemEventHandler):
    def __init__(self, gui_app):
        self.gui_app = gui_app
        self.scan_queue = queue.Queue()
        self.processing_files = set()
        self.scan_thread = threading.Thread(target=self._scan_worker, daemon=True)
        self.scan_thread.start()
        
    def on_created(self, event):
        if not event.is_directory:
            file_path = event.src_path
            if self._is_downloads_folder(file_path) and self._should_scan_file(file_path):
                self.scan_queue.put(("DOWNLOAD", file_path))
                self.gui_app.queue.put((self.gui_app._notify_download_detected, (file_path,)))

    def _is_downloads_folder(self, file_path):
        downloads_path = str(Path.home() / "Downloads")
        return file_path.startswith(downloads_path)

    def _should_scan_file(self, file_path):
        if file_path in self.processing_files:
            return False
        temp_dir = tempfile.gettempdir()
        if file_path.startswith(temp_dir):
            return False
        try:
            if os.path.getsize(file_path) < 100:
                return False
        except:
            return False
        return True

    def _scan_worker(self):
        while True:
            try:
                scan_type, file_path = self.scan_queue.get(timeout=1)
                if file_path and os.path.exists(file_path):
                    self.processing_files.add(file_path)
                    self._scan_single_file(scan_type, file_path)
                    self.processing_files.discard(file_path)
            except queue.Empty:
                continue
            except Exception as e:
                self.gui_app.queue.put((self.gui_app._log_error, (f"Download scan error: {e}",)))

    def _scan_single_file(self, scan_type, file_path):
        try:
            if not CLAMSCAN:
                return
                
            time.sleep(1)
            args = [CLAMSCAN, "--no-summary", file_path]
            result = subprocess.run(args, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 1:
                threat_info = self._extract_threat_info(result.stdout, file_path)
                self.gui_app.queue.put((self.gui_app._add_infected, (file_path, f"{scan_type}: {file_path} - INFECTED", threat_info)))
                self.gui_app.queue.put((self.gui_app._log, (f"🔴 THREAT DETECTED: {os.path.basename(file_path)} - {threat_info.get('type', 'Unknown')}", "infected")))
                self.gui_app.queue.put((self.gui_app._show_alert, (scan_type, file_path, True, threat_info)))
            elif result.returncode == 0:
                self.gui_app.queue.put((self.gui_app._log_info, (f"🟢 CLEAN: {os.path.basename(file_path)}",)))
                if scan_type == "DOWNLOAD":
                    self.gui_app.queue.put((self.gui_app._show_notification, ("Download Verified", f"File is secure: {os.path.basename(file_path)}", "success")))
        except Exception as e:
            self.gui_app.queue.put((self.gui_app._log_error, (f"{scan_type} scan exception: {e}",)))

    def _extract_threat_info(self, output, file_path):
        """Extract threat information from clamscan output"""
        threat_info = {
            'file_path': file_path,
            'file_name': os.path.basename(file_path),
            'type': 'Unknown',
            'description': 'Malicious content detected',
            'risk_level': 'Unknown',
            'detection_time': time.strftime("%Y-%m-%d %H:%M:%S")
        }
        
        # Try to extract malware type from output
        for malware_type in MALWARE_DATABASE.keys():
            if malware_type.lower() in output.lower():
                threat_info['type'] = malware_type
                threat_info.update(MALWARE_DATABASE[malware_type])
                break
                
        # If no specific type found, try to guess from file extension and context
        if threat_info['type'] == 'Unknown':
            file_ext = os.path.splitext(file_path)[1].lower()
            if file_ext in ['.exe', '.dll', '.msi']:
                threat_info['type'] = 'Trojan'
            elif file_ext in ['.doc', '.docx', '.xls', '.xlsx']:
                threat_info['type'] = 'Macro Virus'
            elif file_ext in ['.js', '.vbs', '.ps1']:
                threat_info['type'] = 'Script Virus'
                
            if threat_info['type'] in MALWARE_DATABASE:
                threat_info.update(MALWARE_DATABASE[threat_info['type']])
                
        return threat_info

class RealTimeScanner(FileSystemEventHandler):
    def __init__(self, gui_app):
        self.gui_app = gui_app
        self.scan_queue = queue.Queue()
        self.processing_files = set()
        self.scan_thread = threading.Thread(target=self._scan_worker, daemon=True)
        self.scan_thread.start()
        
    def on_created(self, event):
        if not event.is_directory:
            file_path = event.src_path
            if self._should_scan_file(file_path):
                self.scan_queue.put(("REAL TIME", file_path))
                self.gui_app.queue.put((self.gui_app._log_info, (f"Monitoring: {os.path.basename(file_path)}",)))

    def _should_scan_file(self, file_path):
        if file_path in self.processing_files:
            return False
        temp_dir = tempfile.gettempdir()
        if file_path.startswith(temp_dir):
            return False
        try:
            if os.path.getsize(file_path) < 100:
                return False
        except:
            return False
        risky_extensions = {'.exe', '.dll', '.msi', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.pdf', '.zip', '.rar', '.7z'}
        file_ext = os.path.splitext(file_path)[1].lower()
        return file_ext in risky_extensions

    def _scan_worker(self):
        while True:
            try:
                scan_type, file_path = self.scan_queue.get(timeout=1)
                if file_path and os.path.exists(file_path):
                    self.processing_files.add(file_path)
                    self._scan_single_file(scan_type, file_path)
                    self.processing_files.discard(file_path)
            except queue.Empty:
                continue
            except Exception as e:
                self.gui_app.queue.put((self.gui_app._log_error, (f"Real time scan error: {e}",)))

    def _scan_single_file(self, scan_type, file_path):
        try:
            if not CLAMSCAN:
                return
            time.sleep(0.5)
            args = [CLAMSCAN, "--no-summary", file_path]
            result = subprocess.run(args, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 1:
                threat_info = self._extract_threat_info(result.stdout, file_path)
                self.gui_app.queue.put((self.gui_app._add_infected, (file_path, f"{scan_type}: {file_path} - INFECTED", threat_info)))
                self.gui_app.queue.put((self.gui_app._log, (f"🔴 THREAT: {file_path} - {threat_info.get('type', 'Unknown')}", "infected")))
                self.gui_app.queue.put((self.gui_app._show_alert, (scan_type, file_path, True, threat_info)))
            elif result.returncode == 0:
                self.gui_app.queue.put((self.gui_app._log_info, (f"Scan : {os.path.basename(file_path)} - Secure",)))
        except Exception as e:
            self.gui_app.queue.put((self.gui_app._log_error, (f"Real time scan exception: {e}",)))

    def _extract_threat_info(self, output, file_path):
        """Extract threat information from clamscan output"""
        threat_info = {
            'file_path': file_path,
            'file_name': os.path.basename(file_path),
            'type': 'Unknown',
            'description': 'Malicious content detected',
            'risk_level': 'Unknown',
            'detection_time': time.strftime("%Y-%m-%d %H:%M:%S")
        }
        
        for malware_type in MALWARE_DATABASE.keys():
            if malware_type.lower() in output.lower():
                threat_info['type'] = malware_type
                threat_info.update(MALWARE_DATABASE[malware_type])
                break
                
        if threat_info['type'] == 'Unknown':
            file_ext = os.path.splitext(file_path)[1].lower()
            if file_ext in ['.exe', '.dll', '.msi']:
                threat_info['type'] = 'Trojan'
            elif file_ext in ['.doc', '.docx', '.xls', '.xlsx']:
                threat_info['type'] = 'Macro Virus'
            elif file_ext in ['.js', '.vbs', '.ps1']:
                threat_info['type'] = 'Script Virus'
                
            if threat_info['type'] in MALWARE_DATABASE:
                threat_info.update(MALWARE_DATABASE[threat_info['type']])
                
        return threat_info

def detect_removable_drives():
    drives = []
    system = platform.system()
    if system == "Windows":
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            DRIVE_REMOVABLE = 2
            for c in range(ord('A'), ord('Z')+1):
                letter = f"{chr(c)}:\\"
                if os.path.exists(letter):
                    typ = kernel32.GetDriveTypeW(letter)
                    if typ == DRIVE_REMOVABLE:
                        drives.append(letter)
        except Exception:
            for c in range(ord('A'), ord('Z')+1):
                letter = f"{chr(c)}:\\"
                if os.path.exists(letter):
                    if os.path.exists(os.path.join(letter, "autorun.inf")):
                        drives.append(letter)
    else:
        user = os.environ.get("USER") or os.environ.get("USERNAME") or ""
        candidates = [f"/media/{user}", f"/run/media/{user}", "/media", "/mnt", "/Volumes"]
        for base in candidates:
            if os.path.isdir(base):
                for entry in os.listdir(base):
                    full = os.path.join(base, entry)
                    if os.path.ismount(full):
                        drives.append(full)
    return drives

def run_clamscan_stream(targets, recursive=True, on_update=None):
    if not CLAMSCAN:
        raise FileNotFoundError("clamscan not found in App/CLAMAV or on PATH.")
    args = [CLAMSCAN]
    if recursive:
        args.append("-r")
    if isinstance(targets, (list, tuple)):
        args.extend(map(str, targets))
    else:
        args.append(str(targets))
    args.append("--no-summary")

    proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)

    try:
        for line in proc.stdout:
            if line is None:
                break
            line = line.rstrip("\n")
            if on_update:
                on_update(line)
    except Exception:
        pass

    proc.wait()
    return proc.returncode

class CyberCorpScanner:
    def __init__(self, root):
        self.root = root
        self.setup_window()
        self.queue = queue.Queue()
        self.realtime_scanner = None
        self.download_scanner = None
        self.usb_notifier = None
        self.file_observer = None
        self.notification_system = ProfessionalNotification(self)
        self.virustotal_scanner = VirusTotalScanner(VIRUSTOTAL_API_KEY)
        self.background_service = BackgroundService(self)
        self.monitoring_paths = []
        self.protection_active = False
        self.current_scan_process = None
        self.is_scanning = False
        self.infected_files = []  # Store infected files with threat info
        self.threat_database = {}  # Store threat information
        
        self.setup_ui()
        self._reset_counters()
        self.root.after(150, self._poll_queue)
        
        # Start protection automatically on startup
        self.start_realtime_protection()


    def setup_window(self):
        """Setup main window with professional styling"""
        self.root.title("CyberCorp")
        self.root.geometry("1200x800")
        self.root.configure(bg='#0f172a')
        self.root.minsize(1000, 700)
        
        # Center window on screen
        self.root.update_idletasks()
        x = (self.root.winfo_screenwidth() // 2) - (1200 // 2)
        y = (self.root.winfo_screenheight() // 2) - (800 // 2)
        self.root.geometry(f"1200x800+{x}+{y}")

        # Set window icon
        try:
            self.root.iconbitmap(default=os.path.join(SCRIPT_DIR, "icon.ico"))
        except:
            pass

    def setup_ui(self):
        """Setup professional security interface"""
        # Main container
        main_container = tk.Frame(self.root, bg='#0f172a')
        main_container.pack(fill='both', expand=True, padx=20, pady=20)
        
        # Header
        header_frame = tk.Frame(main_container, bg='#0f172a')
        header_frame.pack(fill='x', pady=(0, 20))
        
        # Logo and title
        logo_frame = tk.Frame(header_frame, bg='#0f172a')
        logo_frame.pack(side='left')
        
        logo_label = tk.Label(logo_frame, text="🛡️", font=('Arial', 24), 
                             fg='#3b82f6', bg='#0f172a')
        logo_label.pack(side='left')
        
        title_frame = tk.Frame(logo_frame, bg='#0f172a')
        title_frame.pack(side='left', padx=(10, 0))
        
        title_label = tk.Label(title_frame, text="CyberCorp", font=('Arial', 24, 'bold'), 
                              fg='#f8fafc', bg='#0f172a')
        title_label.pack(anchor='w')
        
        # Status indicator
        status_frame = tk.Frame(header_frame, bg='#0f172a')
        status_frame.pack(side='right')
        
        self.protection_var = tk.StringVar(value="PROTECTED")
        status_label = tk.Label(status_frame, textvariable=self.protection_var, 
                               font=('Arial', 11, 'bold'), fg='#10b981', bg='#0f172a')
        status_label.pack(anchor='e')
        
        status_subtitle = tk.Label(status_frame, text="Potection active", 
                                  font=('Arial', 9), fg='#64748b', bg='#0f172a')
        status_subtitle.pack(anchor='e')
        
        # Quick Actions Panel
        actions_frame = tk.Frame(main_container, bg='#1e293b', relief='flat', bd=1)
        actions_frame.pack(fill='x', pady=(0, 20))
        
        # Quick actions title
        actions_title = tk.Label(actions_frame, text="QUICK ACTIONS", 
                                font=('Arial', 10, 'bold'), fg='#94a3b8', bg='#1e293b')
        actions_title.pack(anchor='w', padx=15, pady=(12, 8))
        
        # Action buttons
        button_frame = tk.Frame(actions_frame, bg='#1e293b')
        button_frame.pack(fill='x', padx=15, pady=(0, 15))
        
        actions = [
            ("🔍 Full Scan", self.quick_scan),
            ("🚀 Quick Scan", self.full_scan),
            ("📁 Custom Scan", self.custom_scan),
            ("💾 USB Scanner", self.usb_scan),
        ]
        
        for text, command in actions:
            btn = tk.Button(button_frame, text=text, command=command,
                          font=('Arial', 10), fg='#e2e8f0', bg='#334155',
                          activeforeground='#e2e8f0', activebackground='#475569',
                          relief='flat', bd=0, padx=20, pady=12, cursor='hand2')
            btn.pack(side='left', padx=(0, 10))
        
        # Protection control buttons
        protection_frame = tk.Frame(button_frame, bg='#1e293b')
        protection_frame.pack(side='right')
        
        # Start Protection Button
        self.start_btn = tk.Button(protection_frame, text="▶ Start Protection", 
                                 command=self.start_realtime_protection,
                                 font=('Arial', 10, 'bold'), fg='#ffffff', bg='#10b981',
                                 activeforeground='#ffffff', activebackground='#059669',
                                 relief='flat', bd=0, padx=20, pady=12, cursor='hand2')
        self.start_btn.pack(side='left', padx=(0, 10))
        
        # Stop Protection Button
        self.stop_btn = tk.Button(protection_frame, text="⏹ Stop Protection", 
                                command=self.stop_realtime_protection,
                                font=('Arial', 10, 'bold'), fg='#ffffff', bg='#ef4444',
                                activeforeground='#ffffff', activebackground='#dc2626',
                                relief='flat', bd=0, padx=20, pady=12, cursor='hand2')
        self.stop_btn.pack(side='left')
        
        # Stop Scan Button (initially hidden)
        self.stop_scan_btn = tk.Button(protection_frame, text="⏹ Stop Scan", 
                                     command=self.stop_current_scan,
                                     font=('Arial', 10, 'bold'), fg='#ffffff', bg='#f59e0b',
                                     activeforeground='#ffffff', activebackground='#d97706',
                                     relief='flat', bd=0, padx=20, pady=12, cursor='hand2')
        self.stop_scan_btn.pack(side='left', padx=(10, 0))
        self.stop_scan_btn.pack_forget()  # Hide initially
        
        # Initially disable stop button since protection starts automatically
        self.stop_btn.config(state='normal')
        self.start_btn.config(state='disabled')
        
        # Minimize to Tray button
        self.tray_btn = tk.Button(protection_frame, text="📋 Run in Background", 
                                command=self.minimize_to_tray,
                                font=('Arial', 10), fg='#e2e8f0', bg='#6366f1',
                                activeforeground='#e2e8f0', activebackground='#4f46e5',
                                relief='flat', bd=0, padx=20, pady=12, cursor='hand2')
        self.tray_btn.pack(side='left', padx=(10, 0))
        
        # Stats Panel
        stats_frame = tk.Frame(main_container, bg='#1e293b', relief='flat', bd=1)
        stats_frame.pack(fill='x', pady=(0, 20))
        
        stats_title = tk.Label(stats_frame, text="SECURITY STATUS", 
                              font=('Arial', 10, 'bold'), fg='#94a3b8', bg='#1e293b')
        stats_title.pack(anchor='w', padx=15, pady=(12, 15))
        
        stats_grid = tk.Frame(stats_frame, bg='#1e293b')
        stats_grid.pack(fill='x', padx=15, pady=(0, 15))
        
        # Statistics
        self.scanned_var = tk.IntVar(value=0)
        self.infected_var = tk.IntVar(value=0)
        
        stats_data = [
            ("Files Scanned", self.scanned_var, "#3b82f6"),
            ("Threats Blocked", self.infected_var, "#ef4444"),
        ]
        
        for i, (label, var, color) in enumerate(stats_data):
            stat_frame = tk.Frame(stats_grid, bg='#1e293b')
            stat_frame.pack(side='left', padx=(0, 30))
            
            value_label = tk.Label(stat_frame, textvariable=var, font=('Arial', 24, 'bold'),
                                 fg=color, bg='#1e293b')
            value_label.pack()
            
            name_label = tk.Label(stat_frame, text=label, font=('Arial', 10),
                                fg='#94a3b8', bg='#1e293b')
            name_label.pack()
        
        # Main Content Area
        content_frame = tk.Frame(main_container, bg='#0f172a')
        content_frame.pack(fill='both', expand=True)
        
        # Left side - Activity Log
        log_frame = tk.Frame(content_frame, bg='#1e293b', relief='flat', bd=1)
        log_frame.pack(side='left', fill='both', expand=True, padx=(0, 10))
        
        log_header = tk.Frame(log_frame, bg='#1e293b')
        log_header.pack(fill='x', padx=15, pady=12)
        
        log_title = tk.Label(log_header, text="SECURITY ACTIVITY", 
                           font=('Arial', 10, 'bold'), fg='#94a3b8', bg='#1e293b')
        log_title.pack(side='left')
        
        # Scan status
        self.scan_status_var = tk.StringVar(value="Ready")
        scan_status_label = tk.Label(log_header, textvariable=self.scan_status_var,
                                   font=('Arial', 9), fg='#f59e0b', bg='#1e293b')
        scan_status_label.pack(side='right')
        
        # Log area
        log_container = tk.Frame(log_frame, bg='#1e293b')
        log_container.pack(fill='both', expand=True, padx=15, pady=(0, 15))
        
        self.log = scrolledtext.ScrolledText(log_container, wrap="word", 
                                           font=('Consolas', 9), 
                                           bg='#0f172a', fg='#e2e8f0',
                                           insertbackground='#e2e8f0',
                                           relief='flat', bd=0)
        self.log.pack(fill='both', expand=True)
        
        # Configure log tags
        self.log.tag_configure("infected", foreground='#ef4444')
        self.log.tag_configure("info", foreground='#3b82f6')
        self.log.tag_configure("success", foreground='#10b981')
        self.log.tag_configure("warning", foreground='#f59e0b')
        
        # Right side - Threat Management
        threat_frame = tk.Frame(content_frame, bg='#1e293b', relief='flat', bd=1, width=400)
        threat_frame.pack(side='right', fill='both', padx=(10, 0))
        threat_frame.pack_propagate(False)
        
        threat_header = tk.Frame(threat_frame, bg='#1e293b')
        threat_header.pack(fill='x', padx=15, pady=12)
        
        threat_title = tk.Label(threat_header, text="DETECTED THREATS", 
                              font=('Arial', 10, 'bold'), fg='#94a3b8', bg='#1e293b')
        threat_title.pack(side='left')
        
        threat_count = tk.Label(threat_header, textvariable=self.infected_var,
                              font=('Arial', 10, 'bold'), fg='#ef4444', bg='#1e293b')
        threat_count.pack(side='right')
        
        # Threat list and details container
        threat_content = tk.Frame(threat_frame, bg='#1e293b')
        threat_content.pack(fill='both', expand=True, padx=15, pady=(0, 15))
        
        # Threat list frame
        threat_list_frame = tk.Frame(threat_content, bg='#1e293b')
        threat_list_frame.pack(fill='both', expand=True)
        
        # Threat list with scrollbar
        list_container = tk.Frame(threat_list_frame, bg='#1e293b')
        list_container.pack(fill='both', expand=True)
        
        self.infected_listbox = tk.Listbox(list_container, 
                                         bg='#0f172a', fg='#e2e8f0',
                                         selectbackground='#334155',
                                         relief='flat', bd=0,
                                         font=('Consolas', 9))
        
        list_scrollbar = tk.Scrollbar(list_container, orient='vertical')
        list_scrollbar.pack(side='right', fill='y')
        
        self.infected_listbox.config(yscrollcommand=list_scrollbar.set)
        list_scrollbar.config(command=self.infected_listbox.yview)
        
        self.infected_listbox.pack(side='left', fill='both', expand=True)
        self.infected_listbox.bind("<<ListboxSelect>>", self._on_infected_select)
        
        # Threat action buttons
        action_frame = tk.Frame(threat_list_frame, bg='#1e293b')
        action_frame.pack(fill='x', pady=(10, 0))
        
        self.delete_btn = tk.Button(action_frame, text="🗑️ Delete Threat", 
                                  command=self._delete_selected_threat,
                                  font=('Arial', 9, 'bold'), fg='#ffffff', bg='#ef4444',
                                  activeforeground='#ffffff', activebackground='#dc2626',
                                  relief='flat', bd=0, padx=15, pady=8, cursor='hand2')
        self.delete_btn.pack(side='left', padx=(0, 10))
        self.delete_btn.config(state='disabled')
        
        self.quarantine_btn = tk.Button(action_frame, text="📦 Quarantine", 
                                      command=self._quarantine_selected_threat,
                                      font=('Arial', 9), fg='#e2e8f0', bg='#f59e0b',
                                      activeforeground='#e2e8f0', activebackground='#d97706',
                                      relief='flat', bd=0, padx=15, pady=8, cursor='hand2')
        self.quarantine_btn.pack(side='left')
        self.quarantine_btn.config(state='disabled')
        
        # Threat details frame
        details_frame = tk.Frame(threat_content, bg='#1e293b')
        details_frame.pack(fill='x', pady=(15, 0))

    def minimize_to_tray(self):
        """Minimize application to system tray"""
        if messagebox.askyesno("Run in Background", 
                             "CyberCorp will continue running in the background.\n\n"
                             "Real-time protection will remain active.\n"):
            self.background_service.run_in_background()

    def _update_protection_buttons(self):
        """Update button states based on protection status"""
        if self.protection_active:
            self.start_btn.config(state='disabled', bg='#374151', fg='#9ca3af')
            self.stop_btn.config(state='normal', bg='#ef4444', fg='#ffffff')
        else:
            self.start_btn.config(state='normal', bg='#10b981', fg='#ffffff')
            self.stop_btn.config(state='disabled', bg='#374151', fg='#9ca3af')

    def _show_stop_scan_button(self):
        """Show the stop scan button"""
        self.stop_scan_btn.pack(side='left', padx=(10, 0))

    def _hide_stop_scan_button(self):
        """Hide the stop scan button"""
        self.stop_scan_btn.pack_forget()

    def stop_current_scan(self):
        """Stop the currently running scan"""
        if self.current_scan_process and self.is_scanning:
            try:
                self.current_scan_process.terminate()
                self.is_scanning = False
                self.queue.put((self._log_warning, ("Scan stopped by user",)))
                self.queue.put((self.scan_status_var.set, ("Scan stopped",)))
                self._hide_stop_scan_button()
                self._show_notification("Scan Stopped", "Current scan has been stop", "warning")
            except Exception as e:
                self.queue.put((self._log_error, (f"Error stopping scan: {e}",)))
        
        # Also stop VirusTotal scanner if it's running
        if hasattr(self, 'virustotal_scanner') and self.virustotal_scanner.is_scanning:
            self.virustotal_scanner.stop_scan()
            self.is_scanning = False
            self.queue.put((self._log_warning, ("Scan stopped by user",)))
            self.queue.put((self.scan_status_var.set, ("Scan stopped",)))
            self._hide_stop_scan_button()
            self._show_notification("Scan Stopped", "Scan has been stop", "warning")

    def _notify_usb_detected(self, drive_path):
        """Professional USB detection notification"""
        if not self.protection_active:
            return  # Don't scan if protection is disabled
            
        drive_name = os.path.basename(drive_path.rstrip('\\'))
        self._log_info(f"USB device detected: {drive_path}")
        
        self._show_notification("USB Device Connected", 
                              f"Scanning {drive_name} drive for threats...", 
                              "info")
        
        threading.Thread(target=self._scan_usb_worker, args=([drive_path],), daemon=True).start()

    def _notify_download_detected(self, file_path):
        if not self.protection_active:
            return  # Don't scan if protection is disabled
            
        filename = os.path.basename(file_path)
        self._log_info(f"Download scan: {filename}")
        self._show_notification("File Download", f"Scanning: {filename}", "info")

    def _show_alert(self, scan_type, file_path, is_infected, threat_info=None):
        filename = os.path.basename(file_path)
        if is_infected:
            threat_type = threat_info.get('type', 'Unknown') if threat_info else 'Unknown'
            self._show_notification("🚨 THREAT DETECTED", 
                                  f"{threat_type} found:\n{filename}", 
                                  "danger")
        else:
            if scan_type == "DOWNLOAD":
                self._show_notification("✅ Download Secure", 
                                      f"File verified safe:\n{filename}", 
                                      "success")

    def _show_notification(self, title, message, notification_type="info", duration=5000):
        self.notification_system.show_notification(title, message, notification_type, duration)

    def start_realtime_protection(self):
        """Start real-time protection"""
        try:
            if not CLAMSCAN:
                self._log_error("Security engine unavailable")
                messagebox.showerror("Error", "ClamAV engine not found. Please install ClamAV in the CLAMAV folder.")
                return
                
            if self.protection_active:
                self._log_info("Protection already active")
                return
                
            self.realtime_scanner = RealTimeScanner(self)
            self.download_scanner = DownloadScanner(self)
            self.usb_notifier = USBNotifier(self)
            
            user_dirs = [
                str(Path.home() / "Downloads"),
                str(Path.home() / "Desktop"), 
                str(Path.home() / "Documents"),
            ]
            
            self.file_observer = Observer()
            for directory in user_dirs:
                if os.path.exists(directory):
                    if directory == str(Path.home() / "Downloads"):
                        self.file_observer.schedule(self.download_scanner, directory, recursive=True)
                    else:
                        self.file_observer.schedule(self.realtime_scanner, directory, recursive=True)
                    self.monitoring_paths.append(directory)
            
            if self.monitoring_paths:
                self.file_observer.start()
                self.protection_active = True
                self._update_protection_buttons()
                
                self._log_info("🛡️ Real time protection activated")
                self._log_info(f"Monitoring: {', '.join([os.path.basename(p) for p in self.monitoring_paths])}")
                self.protection_var.set("🟢 PROTECTED")
                
                self._show_notification("CyberCorp Active",
                                      "Monitoring actived",
                                      "success")
            else:
                self._log_error("No valid directories found for monitoring")
                
        except Exception as e:
            self._log_error(f"Failed to start protection: {e}")
            messagebox.showerror("Error", f"Failed to start protection: {str(e)}")

    def stop_realtime_protection(self):
        """Stop real time protection"""
        if not self.protection_active:
            self._log_info("Protection already stopped")
            return
            
        # Confirm with user
        if not messagebox.askyesno("Stop Protection", 
                                 "Are you sure you want to stop Protectioning your sYstem?\n\n"):
            return
            
        try:
            if self.file_observer:
                self.file_observer.stop()
                self.file_observer.join()
                self.file_observer = None
                
            if self.usb_notifier:
                self.usb_notifier.stop()
                self.usb_notifier = None
                
            self.realtime_scanner = None
            self.download_scanner = None
            self.monitoring_paths = []
            self.protection_active = False
            self._update_protection_buttons()
            
            self._log_info("🛑 Real time protection disabled")
            self.protection_var.set("🔴 UNPROTECTED")
            self._show_notification("Protection Disabled", 
                                  "Your system is now vulnerable", 
                                  "warning")
                                  
        except Exception as e:
            self._log_error(f"Error stopping protection: {e}")
            messagebox.showerror("Error", f"Error stopping protection: {str(e)}")

    def _scan_usb_worker(self, drives):
        """Worker to scan USB drives in background"""
        if not self.protection_active:
            self._log_info("Scan cancelled - Protection disabled")
            return
            
        try:
            self.queue.put((self._log_info, ("Scanning USB device...",)))
            self.queue.put((self.scan_status_var.set, ("Scanning USB...",)))

            def on_line(line):
                if line.strip() == "":
                    return
                if ":" in line and not line.startswith("[ERR]") and not line.lower().startswith("scan time"):
                    self.queue.put((self._increment_scanned, (1,)))
                if line.endswith("FOUND") or "FOUND" in line or "Infected" in line or "ERROR" in line:
                    path_part = line.split(":")[0] if ":" in line else line
                    threat_info = self._extract_threat_info_from_line(line, path_part)
                    self.queue.put((self._add_infected, (path_part, line, threat_info)))
                    self.queue.put((self._log, (line, "infected")))
                else:
                    self.queue.put((self._log, (line, None)))
                    
            rc = run_clamscan_stream(drives, recursive=True, on_update=on_line)
            
            if rc == 0:
                self.queue.put((self._log_info, ("✅ USB scan complete - No threats found",)))
                self._show_notification("USB Scan Complete", "Device is clean and safe to use", "success")
            elif rc == 1:
                self.queue.put((self._log_info, ("🚨 USB scan complete - Threats detected!",)))
                self._show_notification("🚨 Threat Detected", "Malicious content found on USB device!", "danger")
            else:
                self.queue.put((self._log_error, (f"USB scan error: {rc}",)))
                
        except Exception as e:
            self.queue.put((self._log_error, (f"USB scan failed: {e}",)))
        finally:
            self.queue.put((self._log_info, ("System ready",)))
            self.queue.put((self.scan_status_var.set, ("Ready",)))

    def _extract_threat_info_from_line(self, line, file_path):
        """Extract threat information from scan output line"""
        threat_info = {
            'file_path': file_path,
            'file_name': os.path.basename(file_path),
            'type': 'Unknown',
            'description': 'Malicious content detected',
            'risk_level': 'Unknown',
            'detection_time': time.strftime("%Y-%m-%d %H:%M:%S")
        }
        
        for malware_type in MALWARE_DATABASE.keys():
            if malware_type.lower() in line.lower():
                threat_info['type'] = malware_type
                threat_info.update(MALWARE_DATABASE[malware_type])
                break
                
        if threat_info['type'] == 'Unknown':
            file_ext = os.path.splitext(file_path)[1].lower()
            if file_ext in ['.exe', '.dll', '.msi']:
                threat_info['type'] = 'Trojan'
            elif file_ext in ['.doc', '.docx', '.xls', '.xlsx']:
                threat_info['type'] = 'Macro Virus'
            elif file_ext in ['.js', '.vbs', '.ps1']:
                threat_info['type'] = 'Script Virus'
                
            if threat_info['type'] in MALWARE_DATABASE:
                threat_info.update(MALWARE_DATABASE[threat_info['type']])
                
        return threat_info

    def quit_app(self):
        """Quit application with confirmation"""
        if self.protection_active:
            if not messagebox.askyesno("Quit CyberCorp", 
                                     "Real time protection is active.\n\n"
                                     "Would you like to run CyberCorp in the background?\n\n"):
                # User wants to quit completely
                self.stop_realtime_protection()
                self.root.quit()
                self.root.destroy()
            else:
                # User wants to run in background
                self.minimize_to_tray()
        else:
            self.root.quit()
            self.root.destroy()

    def _reset_counters(self):
        self.scanned_var.set(0)
        self.infected_var.set(0)
        self.infected_files = []
        self.threat_database = {}

    def _log(self, text, tag=None):
        timestamp = time.strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] {text}"
        if tag:
            self.log.insert("end", log_entry + "\n", tag)
        else:
            self.log.insert("end", log_entry + "\n")
        self.log.see("end")

    def _log_info(self, text):
        self._log(text, "info")

    def _log_error(self, text):
        self._log(text, "infected")

    def _log_warning(self, text):
        self._log(text, "warning")

    def _poll_queue(self):
        try:
            while True:
                func, args = self.queue.get_nowait()
                try:
                    func(*args)
                except Exception as e:
                    self._log(f"System error: {e}", "infected")
        except queue.Empty:
            pass
        self.root.after(150, self._poll_queue)

    def _scan_worker(self, targets, recursive=True, scan_type="Manual"):
        """Worker thread for manual scans using ClamAV"""
        try:
            self.is_scanning = True
            self.queue.put((self._log_info, (f"{scan_type} scan in progress...",)))
            self.queue.put((self.scan_status_var.set, (f"{scan_type} scan running...",)))
            self.queue.put((self._show_stop_scan_button, ()))

            def on_line(line):
                if not self.is_scanning:
                    return  # Stop processing if scan was stopped
                if line.strip() == "":
                    return
                if ":" in line and not line.startswith("[ERR]") and not line.lower().startswith("scan time"):
                    self.queue.put((self._increment_scanned, (1,)))
                if line.endswith("FOUND") or "FOUND" in line or "Infected" in line or "ERROR" in line:
                    path_part = line.split(":")[0] if ":" in line else line
                    threat_info = self._extract_threat_info_from_line(line, path_part)
                    self.queue.put((self._add_infected, (path_part, line, threat_info)))
                    self.queue.put((self._log, (line, "infected")))
                else:
                    self.queue.put((self._log, (line, None)))
                    
            # Start the scan process
            if not CLAMSCAN:
                raise FileNotFoundError("clamscan not found")
                
            args = [CLAMSCAN]
            if recursive:
                args.append("-r")
            if isinstance(targets, (list, tuple)):
                args.extend(map(str, targets))
            else:
                args.append(str(targets))
            args.append("--no-summary")

            self.current_scan_process = subprocess.Popen(
                args, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE, 
                text=True, 
                bufsize=1
            )

            # Stream output
            for line in self.current_scan_process.stdout:
                if not self.is_scanning:
                    break
                line = line.rstrip("\n")
                on_line(line)

            # Wait for process completion if not stopped
            if self.is_scanning:
                self.current_scan_process.wait()
                rc = self.current_scan_process.returncode
                
                if rc == 0:
                    self.queue.put((self._log_info, ("✅ Scan complete - System secure",)))
                elif rc == 1:
                    self.queue.put((self._log_info, ("🚨 Scan complete - Threats detected",)))
                else:
                    self.queue.put((self._log_error, (f"Scan error: {rc}",)))
                
        except FileNotFoundError as e:
            self.queue.put((self._log_error, (f"Scan engine not available: {e}",)))
        except Exception as e:
            if self.is_scanning:  # Only log error if scan wasn't stopped by user
                self.queue.put((self._log_error, (f"Scan failed: {e}",)))
        finally:
            self.is_scanning = False
            self.current_scan_process = None
            self.queue.put((self._log_info, ("System ready",)))
            self.queue.put((self.scan_status_var.set, ("Ready",)))
            self.queue.put((self._hide_stop_scan_button, ()))

    def _full_scan_with_virustotal_worker(self, scan_path):
        """Worker thread for full scan"""
        try:
            self.is_scanning = True
            self.queue.put((self._log_info, ("Full system scan in progress...",)))
            self.queue.put((self.scan_status_var.set, ("Full system scan running...",)))
            self.queue.put((self._show_stop_scan_button, ()))

            # Get all files in the selected path
            all_files = []
            for root, dirs, files in os.walk(scan_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    try:
                        if os.path.getsize(file_path) <= 32000000:  # 32MB limit
                            all_files.append(file_path)
                    except:
                        continue
            
            total_files = len(all_files)
            self.queue.put((self._log_info, (f"Found {total_files} files to scan ",)))
            
            scanned_count = 0
            infected_count = 0
            
            for file_path in all_files:
                if not self.is_scanning:
                    break
                    
                scanned_count += 1
                self.queue.put((self.scanned_var.set, (scanned_count,)))
                
                filename = os.path.basename(file_path)
                self.queue.put((self.scan_status_var.set, (f"Scanning {scanned_count}/{total_files}: {filename}",)))
                
                def progress_callback(message):
                    if self.is_scanning:
                        self.queue.put((self.scan_status_var.set, (f"{scanned_count}/{total_files}: {message}",)))
                
                # Scan file
                result = self.virustotal_scanner.scan_file(file_path, progress_callback)
            
                if not self.is_scanning:
                    break
                
                if 'error' in result:
                    self.queue.put((self._log_warning, (f"Error for {filename}: {result['error']}",)))
                else:
                    malicious = result.get('malicious', 0)
                    suspicious = result.get('suspicious', 0)
                    total_engines = result.get('total_engines', 0)
                    
                    if malicious > 0 or suspicious > 0:
                        infected_count += 1
                        self.queue.put((self.infected_var.set, (infected_count,)))
                        
                        threat_level = "High" if malicious > 0 else "Medium"
                        threat_info = {
                            'file_path': file_path,
                            'file_name': filename,
                            'type': 'Cloud Detected Threat',
                            'description': f'Detected by {malicious} security engines as malicious, {suspicious} as suspicious',
                            'risk_level': threat_level,
                            'detection_time': result.get('scan_date', time.strftime("%Y-%m-%d %H:%M:%S")),
                            'actions': ['Potential malware', 'Security risk', 'Cloud analysis detected threat'],
                            'removal': 'Delete file immediately and run full system scan'
                        }
                    
                        self.queue.put((self._add_infected, (file_path, f"{file_path} - DETECTED BY {malicious} ENGINES", threat_info)))
                        self.queue.put((self._log, (f"🔴 THREAT: {filename} - Detected by {malicious} security engines", "infected")))
                    else:
                        self.queue.put((self._log_info, (f"🟢 CLEAN: {filename} - Clean by {total_engines} engines",)))
            
            if self.is_scanning:
                if infected_count == 0:
                    self.queue.put((self._log_info, ("✅ Full scan complete - No threats found",)))
                    self._show_notification("Full Scan Complete",
                                          f"Scanned {scanned_count} files threats detected", 
                                          "success")
                else:
                    self.queue.put((self._log_info, (f"🚨 Full Scan complete - {infected_count} threats detected!",)))
                    self._show_notification("Threats Detected",
                                          f"Found {infected_count} malicious files")
                
        except Exception as e:
            if self.is_scanning:
                self.queue.put((self._log_error, (f"Full Scan failed: {e}",)))
        finally:
            self.is_scanning = False
            self.current_scan_process = None
            self.queue.put((self._log_info, ("System ready",)))
            self.queue.put((self.scan_status_var.set, ("Ready",)))
            self.queue.put((self._hide_stop_scan_button, ()))

    def _process_scan_line(self, line):
        """Process individual lines from scan output"""
        if line.strip() == "":
            return
            
        # Count scanned files and detect threats
        if ":" in line and not line.startswith("[ERR]") and not line.lower().startswith("scan time"):
            self.queue.put((self._increment_scanned, (1,)))
            
        if line.endswith("FOUND") or "FOUND" in line or "Infected" in line:
            path_part = line.split(":")[0] if ":" in line else line
            threat_info = self._extract_threat_info_from_line(line, path_part)
            self.queue.put((self._add_infected, (path_part, line, threat_info)))
            self.queue.put((self._log, (line, "infected")))
        else:
            self.queue.put((self._log, (line, None)))

    def _custom_scan_worker(self, file_path):
        """Custom scan"""
        try:
            self.is_scanning = True
            filename = os.path.basename(file_path)
            self.queue.put((self._log_info, (f"Custom scan in progress for: {filename}",)))
            self.queue.put((self.scan_status_var.set, ("Custom scan running...",)))
            self.queue.put((self._show_stop_scan_button, ()))
            
            # Increment scanned counter
            self.queue.put((self._increment_scanned, (1,)))
            
            def progress_callback(message):
                if self.is_scanning:
                    self.queue.put((self.scan_status_var.set, (f"{message}",)))
                    self.queue.put((self._log_info, (f"{message}",)))
        
            # Scan file
            progress_callback("Starting scan...")
            result = self.virustotal_scanner.scan_file(file_path, progress_callback)
        
            if not self.is_scanning:
                self.queue.put((self._log_info, ("Custom scan cancelled",)))
                return  # Stop if scan was cancelled
            
            if 'error' in result:
                error_msg = result['error']
                self.queue.put((self._log_error, (f"Error: {error_msg}",)))
            
                # Provide helpful suggestions based on error type
                if "API key" in error_msg:
                    self.queue.put((self._log_error, ("Please try again later.",)))
                elif "timeout" in error_msg.lower():
                    self.queue.put((self._log_error, ("Servers are busy. Please try again later.",)))
                elif "network" in error_msg.lower():
                    self.queue.put((self._log_error, ("Please check your internet connection",)))
                elif "rate limit" in error_msg:
                    self.queue.put((self._log_error, ("Please wait before trying again.",)))
                
            else:
                malicious = result.get('malicious', 0)
                suspicious = result.get('suspicious', 0)
                total_engines = result.get('total_engines', 0)
                scan_date = result.get('scan_date', '')
            
                if malicious > 0 or suspicious > 0:
                    threat_level = "High" if malicious > 0 else "Medium"
                    threat_info = {
                        'file_path': file_path,
                        'file_name': filename,
                        'type': 'Cloud Detected Threat',
                        'description': f'Detected by {malicious} security engines as malicious, {suspicious} as suspicious',
                        'risk_level': threat_level,
                        'detection_time': scan_date or time.strftime("%Y-%m-%d %H:%M:%S"),
                        'actions': ['Potential malware', 'Security risk', 'Cloud analysis detected threat'],
                        'removal': 'Delete file immediately and run full system scan'
                    }
                
                    self.queue.put((self._add_infected, (file_path, f"CUSTOM: {file_path} - DETECTED BY {malicious} ENGINES", threat_info)))
                    self.queue.put((self._log, (f"🔴 CLOUD THREAT: {filename} - Detected by {malicious} security engines", "infected")))
                    self.queue.put((self._show_notification, ("🚨 Cloud Threat Detected", 
                                                            f"File detected as malicious by {malicious} security engines", 
                                                            "danger")))
                
                    # Log detailed results
                    results = result.get('results', {})
                    if results:
                        detected_engines = [engine for engine, result in results.items() 
                                          if result.get('category') in ['malicious', 'suspicious']]
                        if detected_engines:
                            self.queue.put((self._log_info, (f"Detection engines: {', '.join(detected_engines[:5])}" + 
                                                           ("..." if len(detected_engines) > 5 else ""),)))
                else:
                    self.queue.put((self._log_info, (f"🟢 CLEAN: {filename} - No threats detected by {total_engines} engines",)))
                    self.queue.put((self._show_notification, ("✅ Cloud Scan Complete", 
                                                            f"File verified clean by {total_engines} security engines", 
                                                            "success")))
                
        except Exception as e:
            if self.is_scanning:
                self.queue.put((self._log_error, (f"Custom scan failed: {e}",)))
                self.queue.put((self._log_error, ("Please check your internet connection.!",)))
        finally:
            self.is_scanning = False
            self.current_scan_process = None
            self.queue.put((self._log_info, ("System ready",)))
            self.queue.put((self.scan_status_var.set, ("Ready",)))
            self.queue.put((self._hide_stop_scan_button, ()))

    def _increment_scanned(self, n=1):
        self.scanned_var.set(self.scanned_var.get() + n)

    def _add_infected(self, path, full_line, threat_info):
        if path not in [info['file_path'] for info in self.infected_files]:
            self.infected_files.append(threat_info)
            display_path = path if len(path) < 50 else "..." + path[-47:]
            self.infected_listbox.insert("end", f"{threat_info.get('type', 'Unknown')}: {display_path}")
            self.threat_database[path] = threat_info
        self.infected_var.set(len(self.infected_files))

    def _set_status(self, text):
        pass  # Status is now shown in the header

    def _on_infected_select(self, event):
        sel = self.infected_listbox.curselection()
        if not sel:
            self.delete_btn.config(state='disabled')
            self.quarantine_btn.config(state='disabled')
            return
            
        idx = sel[0]
        if idx < len(self.infected_files):
            threat_info = self.infected_files[idx]
            self._display_threat_details(threat_info)
            self.delete_btn.config(state='normal')
            self.quarantine_btn.config(state='normal')

    def _display_threat_details(self, threat_info):
        """Display detailed information about the selected threat"""
        self.threat_details.config(state='normal')
        self.threat_details.delete('1.0', 'end')
        
        details = f"""THREAT ANALYSIS REPORT
────────────────────────────────────────
File: {threat_info.get('file_name', 'Unknown')}
Path: {threat_info.get('file_path', 'Unknown')}
Type: {threat_info.get('type', 'Unknown')}
Risk Level: {threat_info.get('risk_level', 'Unknown')}
Detection Time: {threat_info.get('detection_time', 'Unknown')}

DESCRIPTION:
{threat_info.get('description', 'No description available')}

ACTIONS:
{chr(10).join(['• ' + action for action in threat_info.get('actions', ['Unknown malicious activities'])])}

RECOMMENDED ACTION:
{threat_info.get('removal', 'Delete the file immediately and run a full system scan.')}
"""
        
        self.threat_details.insert('1.0', details)
        self.threat_details.config(state='disabled')

    def _delete_selected_threat(self):
        """Delete the selected infected file"""
        sel = self.infected_listbox.curselection()
        if not sel:
            return
            
        idx = sel[0]
        if idx >= len(self.infected_files):
            return
            
        threat_info = self.infected_files[idx]
        file_path = threat_info['file_path']
        
        if not messagebox.askyesno("Confirm Deletion", 
                                 f"Are you sure you want to permanently delete this file?\n\n"
                                 f"File: {os.path.basename(file_path)}\n"
                                 f"Type: {threat_info.get('type', 'Unknown')}\n\n"):
            return
            
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
                self._log_info(f"✅ Threat deleted: {os.path.basename(file_path)}")
                self._show_notification("Threat Eliminated", 
                                      f"Malicious file deleted:\n{os.path.basename(file_path)}", 
                                      "success")
                
                # Remove from lists
                self.infected_listbox.delete(idx)
                self.infected_files.pop(idx)
                if file_path in self.threat_database:
                    del self.threat_database[file_path]
                self.infected_var.set(len(self.infected_files))
                
                # Clear details
                self.threat_details.config(state='normal')
                self.threat_details.delete('1.0', 'end')
                self.threat_details.config(state='disabled')
                
                self.delete_btn.config(state='disabled')
                self.quarantine_btn.config(state='disabled')
            else:
                self._log_warning(f"File not found: {file_path}")
                
        except Exception as e:
            self._log_error(f"Failed to delete file: {e}")
            messagebox.showerror("Deletion Error", f"Could not delete file: {str(e)}")

    def _quarantine_selected_threat(self):
        """Quarantine the selected infected file"""
        sel = self.infected_listbox.curselection()
        if not sel:
            return
            
        idx = sel[0]
        if idx >= len(self.infected_files):
            return
            
        threat_info = self.infected_files[idx]
        file_path = threat_info['file_path']
        
        # Create quarantine directory if it doesn't exist
        quarantine_dir = os.path.join(SCRIPT_DIR, "Quarantine")
        os.makedirs(quarantine_dir, exist_ok=True)
        
        try:
            if os.path.exists(file_path):
                # Move file to quarantine
                filename = os.path.basename(file_path)
                quarantine_path = os.path.join(quarantine_dir, f"quarantined_{int(time.time())}_{filename}")
                shutil.move(file_path, quarantine_path)
                
                self._log_info(f"📦 Threat quarantined: {filename}")
                self._show_notification("Threat Quarantined", 
                                      f"Malicious file isolated:\n{filename}", 
                                      "warning")
                
                self.infected_listbox.delete(idx)
                self.infected_files.pop(idx)
                self.infected_var.set(len(self.infected_files))
                
                self.threat_details.config(state='normal')
                self.threat_details.delete('1.0', 'end')
                self.threat_details.config(state='disabled')
                
                self.delete_btn.config(state='disabled')
                self.quarantine_btn.config(state='disabled')
            else:
                self._log_warning(f"File not found: {file_path}")
                
        except Exception as e:
            self._log_error(f"Failed to quarantine file: {e}")
            messagebox.showerror("Quarantine Error", f"Could not quarantine file: {str(e)}")

    def quick_scan(self):
        """Quick Scan"""
        if self.is_scanning:
            messagebox.showinfo("Scan in Progress", "Please stop the current scan before starting a new one.")
            return
            
        home = Path.home()
        tgt = []
        for name in ("Desktop", "Downloads", "Documents"):
            p = home / name
            if p.exists():
                tgt.append(str(p))
        if not tgt:
            messagebox.showinfo("Quick Scan", "No default folders found to scan.")
            return
        self._log_info(f"Starting quick security scan...")
        self._reset_counters()
        threading.Thread(target=self._scan_worker, args=(tgt, True, "Quick"), daemon=True).start()

    def full_scan(self):
        """Full Scan"""
        if self.is_scanning:
            messagebox.showinfo("Scan in Progress", "Please stop the current scan before starting a new one.")
            return
            
        path = filedialog.askdirectory(title="Select folder or drive to Scan")
        if not path:
            return
        
        if not os.path.exists(path):
            messagebox.showerror("Error", "The selected path not exist.")
            return
            
        if not os.access(path, os.R_OK):
            messagebox.showerror("Error", "No read permission for the selected path.")
            return
            
        confirm = messagebox.askyesno(
            "Full Scan", 
            f"WARNING: This will scan ALL files in:\n\n{path}\n\n"
            f"⚠️  Large folders may take a very long time\n"
        )
        
        if not confirm:
            return
    
        self._log_info(f"Starting Quick scan {path}")
        self._reset_counters()
        
        threading.Thread(target=self._full_scan_with_virustotal_worker, args=(path,), daemon=True).start()

    def custom_scan(self):
        """Custom Scan"""
        if self.is_scanning:
            messagebox.showinfo("Scan in Progress", "Please stop the current scan before starting a new one.")
            return
            
        f = filedialog.askopenfilename(title="Select file to Scan")
        if not f:
            return
            
        try:
            file_size = os.path.getsize(f)
            if file_size > 32000000:  # 32MB
                messagebox.showerror("File Too Large", 
                                   "File size exceeds limit (32MB).\nPlease select a smaller file.")
                return
        except:
            pass
            
        self._log_info(f"Starting Custom scan {os.path.basename(f)}")
        self._reset_counters()
        threading.Thread(target=self._custom_scan_worker, args=(f,), daemon=True).start()

    def usb_scan(self):
        """USB Scan - Scan removable drive"""
        if self.is_scanning:
            messagebox.showinfo("Scan in Progress", "Please stop the current scan before starting a new one.")
            return
            
        drives = detect_removable_drives()
        if not drives:
            if messagebox.askyesno("USB Scan", "No removable drives detected. Select a folder to scan?"):
                d = filedialog.askdirectory(title="Select folder to scan")
                if d:
                    drives = [d]
                else:
                    return
            else:
                return
        self._log_info(f"Starting USBsscan...")
        self._reset_counters()
        threading.Thread(target=self._scan_worker, args=(drives, True, "USB"), daemon=True).start()

def main():
    root = tk.Tk()
    app = CyberCorpScanner(root)
    root.protocol("WM_DELETE_WINDOW", app.quit_app)
    root.mainloop()

if __name__ == "__main__":
    main()