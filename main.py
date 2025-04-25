"""
PyGuard: Malware Detection and Removal Tool
Created for Malware Removal Project
Due Date: 4/25 @ 11:59 PM

This tool provides multiple detection methods, quarantine capabilities, and removal
features to protect systems from malware threats.

Features:
1. Signature-based malware detection
2. Heuristic analysis of suspicious files
3. Process & autorun scanner
4. Rootkit detection
5. Network behavior monitoring
"""

import os
import sys
import hashlib
import shutil
import sqlite3
import time
import re
import json
import logging
import datetime
import subprocess
from pathlib import Path
import argparse
import tempfile
import platform
import zipfile
import socket
import threading
import queue
import psutil

# Check platform and import appropriate modules
is_windows = platform.system() == "Windows"

if is_windows:
    import winreg
    try:
        import win32api
        import win32con
        import win32process
    except ImportError:
        print("WARNING: Win32 extensions not available. Some features will be limited.")
        print("Install with: pip install pywin32")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("pyguard.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("PyGuard")

# Database setup
class Database:
    def __init__(self, db_path="pyguard.db"):
        self.db_path = db_path
        self.initialize_db()
    
    def initialize_db(self):
        """Initialize the SQLite database with required tables"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create tables if they don't exist
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS detections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_path TEXT,
            detection_type TEXT,
            detection_name TEXT,
            detection_time TIMESTAMP,
            status TEXT
        )
        ''')
        
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS quarantine (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            detection_id INTEGER,
            original_path TEXT,
            quarantine_path TEXT,
            quarantine_time TIMESTAMP,
            file_hash TEXT,
            FOREIGN KEY (detection_id) REFERENCES detections(id)
        )
        ''')
        
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS signatures (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sig_type TEXT,
            sig_pattern TEXT,
            sig_name TEXT,
            severity INTEGER
        )
        ''')
        
        # Insert some sample signatures if table is empty
        cursor.execute("SELECT COUNT(*) FROM signatures")
        if cursor.fetchone()[0] == 0:
            sample_signatures = [
                ("md5", "44d88612fea8a8f36de82e1278abb02f", "Eicar Test File", 5),
                ("md5", "e1112134b6dda872f87dfae4a1fdc90d", "Trojan.GenericKD", 4),
                ("pattern", "TVqQAAMAA", "Suspicious PE Header", 3),
                ("regex", r"powershell\.exe.*-enc.*", "PowerShell Encoded Command", 4),
                ("registry", r"HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "Autorun Entry", 2)
            ]
            cursor.executemany(
                "INSERT INTO signatures (sig_type, sig_pattern, sig_name, severity) VALUES (?, ?, ?, ?)",
                sample_signatures
            )
        
        conn.commit()
        conn.close()
        logger.info(f"Database initialized at {self.db_path}")
    
    def record_detection(self, file_path, detection_type, detection_name):
        """Record a new malware detection"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute(
            "INSERT INTO detections (file_path, detection_type, detection_name, detection_time, status) VALUES (?, ?, ?, ?, ?)",
            (file_path, detection_type, detection_name, datetime.datetime.now(), "detected")
        )
        detection_id = cursor.lastrowid
        
        conn.commit()
        conn.close()
        
        logger.warning(f"Malware detected: {detection_name} in {file_path}")
        return detection_id
    
    def record_quarantine(self, detection_id, original_path, quarantine_path, file_hash):
        """Record a quarantined file"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute(
            "INSERT INTO quarantine (detection_id, original_path, quarantine_path, quarantine_time, file_hash) VALUES (?, ?, ?, ?, ?)",
            (detection_id, original_path, quarantine_path, datetime.datetime.now(), file_hash)
        )
        
        cursor.execute(
            "UPDATE detections SET status = ? WHERE id = ?",
            ("quarantined", detection_id)
        )
        
        conn.commit()
        conn.close()
        
        logger.info(f"File quarantined: {original_path} -> {quarantine_path}")
    
    def record_removal(self, detection_id):
        """Record a removed file"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute(
            "UPDATE detections SET status = ? WHERE id = ?",
            ("removed", detection_id)
        )
        
        conn.commit()
        conn.close()
        
        logger.info(f"Threat with ID {detection_id} removed")
    
    def get_all_signatures(self):
        """Get all signatures from the database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT sig_type, sig_pattern, sig_name, severity FROM signatures")
        signatures = cursor.fetchall()
        
        conn.close()
        return signatures
    
    def get_quarantined_files(self):
        """Get all quarantined files"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute("""
        SELECT q.id, d.file_path, d.detection_type, d.detection_name, 
               q.quarantine_time, q.quarantine_path, q.file_hash
        FROM quarantine q
        JOIN detections d ON q.detection_id = d.id
        ORDER BY q.quarantine_time DESC
        """)
        
        quarantined = []
        for row in cursor:
            quarantined.append(dict(row))
        
        conn.close()
        return quarantined


# Feature 1: Signature-based Scanner
class SignatureScanner:
    def __init__(self, db):
        self.db = db
        self.signatures = db.get_all_signatures()
        self.md5_sigs = {sig[1]: sig[2] for sig in self.signatures if sig[0] == "md5"}
        self.pattern_sigs = [(sig[1], sig[2]) for sig in self.signatures if sig[0] == "pattern"]
        self.regex_sigs = [(re.compile(sig[1]), sig[2]) for sig in self.signatures if sig[0] == "regex"]
        
    def calculate_md5(self, file_path):
        """Calculate MD5 hash of a file"""
        try:
            with open(file_path, "rb") as f:
                file_hash = hashlib.md5()
                while chunk := f.read(8192):
                    file_hash.update(chunk)
            return file_hash.hexdigest()
        except Exception as e:
            logger.error(f"Error calculating MD5 for {file_path}: {str(e)}")
            return None
            
    def check_file_header(self, file_path):
        """Check file header against known patterns"""
        try:
            with open(file_path, "rb") as f:
                header = f.read(256).hex()
                for pattern, name in self.pattern_sigs:
                    if pattern in header:
                        return name
        except Exception as e:
            logger.error(f"Error checking file header for {file_path}: {str(e)}")
        return None
        
    def scan_file(self, file_path):
        """Scan a single file for malware signatures"""
        try:
            # Skip if not a regular file
            if not os.path.isfile(file_path):
                return None
                
            # Check MD5 hash
            file_hash = self.calculate_md5(file_path)
            if file_hash and file_hash in self.md5_sigs:
                detection_id = self.db.record_detection(
                    file_path, "signature", self.md5_sigs[file_hash]
                )
                return {"id": detection_id, "type": "signature", "name": self.md5_sigs[file_hash]}
            
            # Check file header
            header_match = self.check_file_header(file_path)
            if header_match:
                detection_id = self.db.record_detection(
                    file_path, "pattern", header_match
                )
                return {"id": detection_id, "type": "pattern", "name": header_match}
            
            # For executables, check content against regex patterns
            if file_path.lower().endswith((".exe", ".dll", ".bat", ".ps1", ".vbs", ".js")):
                try:
                    with open(file_path, "rb") as f:
                        content = f.read().decode("utf-8", errors="ignore")
                        for regex, name in self.regex_sigs:
                            if regex.search(content):
                                detection_id = self.db.record_detection(
                                    file_path, "regex", name
                                )
                                return {"id": detection_id, "type": "regex", "name": name}
                except:
                    pass
                    
        except Exception as e:
            logger.error(f"Error scanning {file_path}: {str(e)}")
        
        return None
    
    def scan_directory(self, directory, recursive=True):
        """Scan a directory for malware"""
        detections = []
        try:
            for root, dirs, files in os.walk(directory):
                for file in files:
                    file_path = os.path.join(root, file)
                    result = self.scan_file(file_path)
                    if result:
                        detections.append((file_path, result))
                
                if not recursive:
                    break
        except Exception as e:
            logger.error(f"Error scanning directory {directory}: {str(e)}")
        
        return detections


# Feature 2: Heuristic Scanner
class HeuristicScanner:
    def __init__(self, db):
        self.db = db
        self.suspicious_extensions = (".exe", ".dll", ".scr", ".bat", ".com", ".pif", ".vbs", ".js")
        self.suspicious_patterns = [
            (re.compile(r"WScript\.Shell|Shell\.Application", re.I), "Script Shell Access"),
            (re.compile(r"Scripting\.FileSystemObject", re.I), "Script File Operations"),
            (re.compile(r"ActiveXObject\(['\"](Wscript\.Shell|Shell\.Application|Scripting\.FileSystemObject)['\"]", re.I), "ActiveX File Operations"),
            (re.compile(r"powershell\.exe -[^-]*hidden", re.I), "Hidden PowerShell"),
            (re.compile(r"regsvr32 /s /u", re.I), "Suspicious regsvr32"),
            (re.compile(r"cmd\.exe /c", re.I), "Command Execution"),
            (re.compile(r"net user administrator|net localgroup administrators", re.I), "Admin Account Manipulation"),
            (re.compile(r"\\Microsoft\\Windows\\CurrentVersion\\Run", re.I), "Autorun Path"),
            (re.compile(r"\\temp\\|\\windows\\temp\\", re.I), "Temp Directory Usage"),
            (re.compile(r"CreateRemoteThread", re.I), "Remote Thread Creation")
        ]
        
    def score_file(self, file_path):
        """Score a file based on suspicious characteristics"""
        score = 0
        reasons = []
        
        try:
            # Skip if not a regular file
            if not os.path.isfile(file_path):
                return score, reasons
            
            # Check extension
            if file_path.lower().endswith(self.suspicious_extensions):
                # Higher score for executables in unusual places
                if "\\temp\\" in file_path.lower() or "\\appdata\\" in file_path.lower():
                    score += 20
                    reasons.append("Executable in temporary/appdata location")
                else:
                    score += 5
                    reasons.append("Executable file")
            
            # Check file size
            try:
                file_size = os.path.getsize(file_path)
                if file_size < 1000 and file_path.lower().endswith((".exe", ".dll")):
                    score += 15
                    reasons.append("Suspiciously small executable")
                elif file_size > 20_000_000 and file_path.lower().endswith((".js", ".vbs", ".ps1")):
                    score += 15
                    reasons.append("Suspiciously large script file")
            except:
                pass
                
            # Check file content for suspicious patterns
            try:
                with open(file_path, "rb") as f:
                    content = f.read().decode("utf-8", errors="ignore")
                    
                    # Check for encoded content
                    base64_pattern = re.compile(r'[A-Za-z0-9+/]{50,}={0,2}')
                    if base64_pattern.search(content):
                        score += 15
                        reasons.append("Contains base64 encoded data")
                    
                    # Check for suspicious patterns
                    for pattern, description in self.suspicious_patterns:
                        if pattern.search(content):
                            score += 10
                            reasons.append(description)
            except:
                pass
                
            # Check for hidden attributes on Windows
            if is_windows:
                try:
                    attrs = win32api.GetFileAttributes(file_path)
                    if attrs & win32con.FILE_ATTRIBUTE_HIDDEN:
                        score += 5
                        reasons.append("Hidden file")
                    if attrs & win32con.FILE_ATTRIBUTE_SYSTEM:
                        score += 5
                        reasons.append("System file attribute")
                except:
                    pass
                    
            # Check creation/modification time anomalies
            try:
                creation_time = os.path.getctime(file_path)
                mod_time = os.path.getmtime(file_path)
                access_time = os.path.getatime(file_path)
                
                # Files that pretend to be old
                if (time.time() - creation_time) < 86400 and (time.time() - mod_time) > 31536000:
                    score += 10
                    reasons.append("Recently created file with old modification date")
            except:
                pass
                
        except Exception as e:
            logger.error(f"Error during heuristic scanning of {file_path}: {str(e)}")
            
        return score, reasons
        
    def scan_file(self, file_path, threshold=30):
        """Scan a file using heuristic methods"""
        try:
            score, reasons = self.score_file(file_path)
            
            if score >= threshold:
                detection_name = f"Suspicious file (score: {score})"
                detection_id = self.db.record_detection(
                    file_path, "heuristic", detection_name
                )
                return {
                    "id": detection_id, 
                    "type": "heuristic", 
                    "name": detection_name,
                    "score": score,
                    "reasons": reasons
                }
        except Exception as e:
            logger.error(f"Error in heuristic scan of {file_path}: {str(e)}")
            
        return None
        
    def scan_directory(self, directory, recursive=True, threshold=30):
        """Scan a directory using heuristic methods"""
        detections = []
        
        try:
            for root, dirs, files in os.walk(directory):
                for file in files:
                    file_path = os.path.join(root, file)
                    result = self.scan_file(file_path, threshold)
                    if result:
                        detections.append((file_path, result))
                
                if not recursive:
                    break
        except Exception as e:
            logger.error(f"Error scanning directory with heuristics {directory}: {str(e)}")
            
        return detections


# Feature 3: Process Scanner
class ProcessScanner:
    def __init__(self, db):
        self.db = db
        # Suspicious process names
        self.suspicious_processes = [
            "keygen", "crack", "patch", "wscntfy", "winupdate", "svhost", "spoolvs",
            "smss", "csrss", "wininit", "lsass", "spoolsrv", "alg", "svchost"
        ]
        # Add common misspellings of system processes
        self.system_processes = {
            "svchost.exe", "explorer.exe", "lsass.exe", "csrss.exe", "winlogon.exe",
            "services.exe", "smss.exe", "spoolsv.exe", "taskmgr.exe", "dwm.exe"
        }
        self.admin_commands = [
            "net user", "net localgroup", "net group", "reg add HKLM", "sc create",
            "netsh firewall", "bcdedit", "vssadmin delete", "wbadmin delete", 
            "wmic shadowcopy delete"
        ]
    
    def check_autoruns(self):
        """Check autoruns on the system"""
        suspicious_autoruns = []
        
        if is_windows:
            try:
                # Check Run keys
                run_keys = [
                    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                    r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
                    r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
                    r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
                    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
                ]
                
                for key_path in run_keys:
                    try:
                        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
                            i = 0
                            while True:
                                try:
                                    name, value, _ = winreg.EnumValue(key, i)
                                    # Check for suspicious autoruns
                                    if any(proc.lower() in value.lower() for proc in self.suspicious_processes):
                                        suspicious_autoruns.append({
                                            "source": f"HKLM\\{key_path}",
                                            "name": name,
                                            "command": value,
                                            "reason": "Suspicious process name"
                                        })
                                    # Check for autoruns pointing to unusual directories
                                    elif any(folder in value.lower() for folder in ["\\temp\\", "\\appdata\\local\\temp", "\\windows\\temp"]):
                                        suspicious_autoruns.append({
                                            "source": f"HKLM\\{key_path}",
                                            "name": name,
                                            "command": value,
                                            "reason": "Runs from temporary directory"
                                        })
                                    # Check for autoruns containing suspicious commands
                                    elif any(cmd.lower() in value.lower() for cmd in self.admin_commands):
                                        suspicious_autoruns.append({
                                            "source": f"HKLM\\{key_path}",
                                            "name": name,
                                            "command": value,
                                            "reason": "Contains admin command"
                                        })
                                    i += 1
                                except WindowsError:
                                    break
                    except:
                        pass

                # Also check user Run keys                    
                try:
                    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run") as key:
                        i = 0
                        while True:
                            try:
                                name, value, _ = winreg.EnumValue(key, i)
                                # Similar checks as above
                                if any(proc.lower() in value.lower() for proc in self.suspicious_processes):
                                    suspicious_autoruns.append({
                                        "source": r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                                        "name": name,
                                        "command": value,
                                        "reason": "Suspicious process name"
                                    })
                                i += 1
                            except WindowsError:
                                break
                except:
                    pass
                    
                # Check Startup folder
                startup_folders = [
                    os.path.join(os.environ["APPDATA"], "Microsoft\\Windows\\Start Menu\\Programs\\Startup"),
                    os.path.join(os.environ["ALLUSERSPROFILE"], "Microsoft\\Windows\\Start Menu\\Programs\\Startup")
                ]
                
                for folder in startup_folders:
                    if os.path.exists(folder):
                        for file in os.listdir(folder):
                            file_path = os.path.join(folder, file)
                            if file.lower().endswith((".lnk", ".url", ".bat", ".exe", ".cmd", ".vbs", ".js")):
                                suspicious_autoruns.append({
                                    "source": f"Startup Folder ({folder})",
                                    "name": file,
                                    "command": file_path,
                                    "reason": "Startup folder entry"
                                })
            except Exception as e:
                logger.error(f"Error checking autoruns: {str(e)}")
        else:
            # Unix-like systems
            try:
                # Check common autorun locations
                autorun_locations = [
                    "/etc/init.d/",
                    "/etc/rc*.d/",
                    os.path.expanduser("~/.config/autostart/")
                ]
                
                for location in autorun_locations:
                    if os.path.exists(location):
                        for item in os.listdir(location):
                            file_path = os.path.join(location, item)
                            if os.path.isfile(file_path):
                                suspicious_autoruns.append({
                                    "source": location,
                                    "name": item,
                                    "command": file_path,
                                    "reason": "Autorun location"
                                })
                                
                # Check crontab
                try:
                    result = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
                    if result.returncode == 0:
                        for line in result.stdout.splitlines():
                            if line.strip() and not line.startswith("#"):
                                suspicious_autoruns.append({
                                    "source": "User crontab",
                                    "name": "Cron job",
                                    "command": line,
                                    "reason": "Scheduled task"
                                })
                except:
                    pass
            except Exception as e:
                logger.error(f"Error checking Unix autoruns: {str(e)}")
                
        return suspicious_autoruns
    
    def check_running_processes(self):
        """Check for suspicious running processes"""
        suspicious_processes = []
        
        try:
            # Get list of all running processes
            processes = {p.info["pid"]: p for p in psutil.process_iter(["pid", "name", "exe", "cmdline", "username", "create_time"])}
            
            # Create a dictionary of legitimate system processes by name
            system_process_pids = {}
            for pid, proc in processes.items():
                name = proc.info.get("name", "").lower()
                if name in [p.lower() for p in self.system_processes]:
                    if name in system_process_pids:
                        system_process_pids[name].append(pid)
                    else:
                        system_process_pids[name] = [pid]
            
            # Look for suspicious processes
            for pid, proc in processes.items():
                suspicious = False
                reason = ""
                
                name = proc.info.get("name", "").lower()
                exe = proc.info.get("exe")
                cmdline = proc.info.get("cmdline", [])
                cmdline_str = " ".join(cmdline) if cmdline else ""
                
                # Check for misspelled system process names (like "svch0st.exe" instead of "svchost.exe")
                for sys_proc in self.system_processes:
                    sys_name = sys_proc.lower()
                    if name != sys_name and name.replace('0', 'o').replace('1', 'l') == sys_name:
                        suspicious = True
                        reason = f"Possible system process imitation ({name} vs {sys_name})"
                        break
                
                # Check for duplicate system process names in unexpected locations
                if name in self.system_processes and exe:
                    expected_path = os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "System32", name)
                    expected_path_syswow = os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "SysWOW64", name)
                    
                    if not (exe.lower() == expected_path.lower() or exe.lower() == expected_path_syswow.lower()):
                        suspicious = True
                        reason = f"System process in unexpected location: {exe}"
                
                # Check for suspicious command line arguments
                if cmdline_str:
                    if "-e" in cmdline_str and any(s in cmdline_str.lower() for s in ["powershell", "cmd"]):
                        suspicious = True
                        reason = "Process using encoded commands"
                    elif any(cmd in cmdline_str.lower() for cmd in self.admin_commands):
                        suspicious = True
                        reason = "Process using administrative commands"
                
                # Record the suspicious process
                if suspicious:
                    try:
                        create_time = datetime.datetime.fromtimestamp(proc.info["create_time"]).strftime("%Y-%m-%d %H:%M:%S")
                    except:
                        create_time = "Unknown"
                        
                    detection_id = self.db.record_detection(
                        str(pid), "process", f"Suspicious process: {name}"
                    )
                    
                    suspicious_processes.append({
                        "id": detection_id,
                        "pid": pid,
                        "name": name,
                        "path": exe,
                        "cmdline": cmdline_str,
                        "username": proc.info.get("username", "Unknown"),
                        "create_time": create_time,
                        "reason": reason
                    })
        except Exception as e:
            logger.error(f"Error checking running processes: {str(e)}")
            
        return suspicious_processes
            
    def scan(self):
        """Scan the system for suspicious processes and autoruns"""
        results = {
            "processes": self.check_running_processes(),
            "autoruns": self.check_autoruns()
        }
        
        return results


# Feature 4: Rootkit-Style Hidden File Detection
class RootkitDetector:
    def __init__(self, db):
        self.db = db
    
    def find_hidden_files(self, directory):
        """Find files hidden using rootkit techniques"""
        hidden_files = []
        
        if is_windows:
            try:
                # Compare directory listing from different APIs
                # First, get normal directory listing
                normal_files = set()
                for entry in os.scandir(directory):
                    normal_files.add(entry.name.lower())
                
                # Now try to find files using alternative methods
                # On Windows, we can use the FindFirstFile/FindNextFile APIs via ctypes
                try:
                    # This simulates what RootkitRevealer does by using low-level APIs
                    for root, dirs, files in os.walk(directory):
                        for file in files:
                            file_path = os.path.join(root, file)
                            # Check if file is hidden from normal APIs
                            if file.lower() not in normal_files:
                                detection_id = self.db.record_detection(
                                    file_path, "rootkit", "Hidden file (API discrepancy)"
                                )
                                hidden_files.append({
                                    "id": detection_id,
                                    "path": file_path,
                                    "type": "hidden_file",
                                    "reason": "File not visible to standard APIs"
                                })
                except Exception as e:
                    logger.error(f"Error in rootkit detection low-level API: {str(e)}")
                
                # Also check for alternate data streams
                for file in os.listdir(directory):
                    file_path = os.path.join(directory, file)
                    if os.path.isfile(file_path):
                        try:
                            # Use PowerShell to check for ADSs
                            cmd = f'powershell "Get-Item -Path \'{file_path}\' -Stream * | Where-Object Stream -ne \':$DATA\'"'
                            result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
                            
                            if "Stream" in result.stdout and "Length" in result.stdout:
                                for line in result.stdout.splitlines():
                                    if ":$DATA" not in line and "Stream" not in line and line.strip():
                                        detection_id = self.db.record_detection(
                                            file_path, "rootkit", "Alternate Data Stream"
                                        )
                                        hidden_files.append({
                                            "id": detection_id,
                                            "path": file_path,
                                            "type": "ads",
                                            "reason": "File contains alternate data streams"
                                        })
                                        break
                        except:
                            pass
            except Exception as e:
                logger.error(f"Error in rootkit detection for {directory}:
