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
                logger.error(f"Error in rootkit detection for {directory}: {str(e)}")
        else:
            # Unix-like systems
            try:
                # Compare standard listing with direct device access
                normal_files = set()
                for entry in os.scandir(directory):
                    normal_files.add(entry.name.lower())
                
                # On Unix-like systems, check for hidden files (starting with .)
                for file in os.listdir(directory):
                    if file.startswith('.') and file not in ['.', '..']:
                        file_path = os.path.join(directory, file)
                        if os.path.isfile(file_path):
                            detection_id = self.db.record_detection(
                                file_path, "rootkit", "Hidden file (Unix)"
                            )
                            hidden_files.append({
                                "id": detection_id,
                                "path": file_path, 
                                "type": "unix_hidden",
                                "reason": "Unix hidden file"
                            })
            except Exception as e:
                logger.error(f"Error in Unix rootkit detection for {directory}: {str(e)}")
                
        return hidden_files
    
    def check_syscall_hooks(self):
        """Check for potential syscall hooks (advanced rootkit detection)"""
        hooks = []
        
        if is_windows:
            try:
                # Check for SSDT hooks by looking at unexpected DLLs in system processes
                processes = {p.info["pid"]: p for p in psutil.process_iter(["pid", "name", "exe"])}
                
                for pid, proc in processes.items():
                    name = proc.info.get("name", "").lower()
                    
                    # Focus on key system processes
                    if name in ["svchost.exe", "lsass.exe", "winlogon.exe", "services.exe"]:
                        try:
                            # Get modules loaded by the process
                            proc_handle = psutil.Process(pid)
                            loaded_modules = proc_handle.memory_maps()
                            
                            for module in loaded_modules:
                                module_path = module.path.lower()
                                
                                # Look for suspicious modules not in system32
                                if (not module_path.startswith(os.environ.get("SystemRoot", "C:\\Windows").lower()) and 
                                    not module_path.startswith("\\??\\" + os.environ.get("SystemRoot", "C:\\Windows").lower())):
                                    
                                    detection_id = self.db.record_detection(
                                        module_path, "rootkit", f"Suspicious module in {name}"
                                    )
                                    
                                    hooks.append({
                                        "id": detection_id,
                                        "process": name,
                                        "process_id": pid,
                                        "module": module_path,
                                        "reason": f"Non-system DLL loaded in {name}"
                                    })
                        except:
                            # Permission errors are expected for some processes
                            pass
            except Exception as e:
                logger.error(f"Error checking syscall hooks: {str(e)}")
        else:
            # For Unix systems, we could check /proc for unusual entries
            try:
                if os.path.exists("/proc"):
                    # Example: check for suspicious kernel modules
                    try:
                        with open("/proc/modules", "r") as f:
                            modules = f.readlines()
                            
                            # Get list of official modules
                            official_modules = set()
                            try:
                                result = subprocess.run(["modprobe", "-l"], capture_output=True, text=True)
                                if result.returncode == 0:
                                    official_modules = set(line.strip() for line in result.stdout.splitlines())
                            except:
                                pass
                            
                            for line in modules:
                                module_name = line.split()[0]
                                if module_name not in official_modules:
                                    detection_id = self.db.record_detection(
                                        module_name, "rootkit", "Suspicious kernel module"
                                    )
                                    hooks.append({
                                        "id": detection_id,
                                        "module": module_name,
                                        "reason": "Suspicious kernel module"
                                    })
                    except Exception as e:
                        logger.error(f"Error checking /proc/modules: {str(e)}")
            except Exception as e:
                logger.error(f"Error in Unix syscall hook detection: {str(e)}")
                
        return hooks
    
    def scan(self, directories=None):
        """Perform rootkit scanning"""
        results = {
            "hidden_files": [],
            "syscall_hooks": self.check_syscall_hooks()
        }
        
        # If no directories specified, scan system directories
        if not directories:
            if is_windows:
                directories = [
                    os.environ.get("SystemRoot", "C:\\Windows"),
                    os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "System32"),
                    os.environ.get("TEMP", "C:\\Windows\\Temp"),
                    os.environ.get("APPDATA", os.path.expanduser("~\\AppData\\Roaming"))
                ]
            else:
                directories = [
                    "/bin", 
                    "/usr/bin", 
                    "/sbin", 
                    "/tmp", 
                    os.path.expanduser("~")
                ]
        
        # Scan each directory
        for directory in directories:
            if os.path.exists(directory) and os.path.isdir(directory):
                hidden_files = self.find_hidden_files(directory)
                results["hidden_files"].extend(hidden_files)
                
        return results


# Feature 5: Network Monitor
class NetworkMonitor:
    def __init__(self, db):
        self.db = db
        self.suspicious_domains = [
            "evil.com", "malware.com", "hack.com", "badserver.net", "malicious.org",
            "botnet.cc", "trojan.ru", "virus.cn", "backdoor.io", "exploit-db.com"
        ]
        self.suspicious_ips = [
            "1.2.3.4", "10.0.0.99", "192.168.1.200", "127.0.0.2"  # Example IPs, should be replaced with actual known-bad IPs
        ]
        self.monitoring = False
        self.monitor_thread = None
        self.connections_queue = queue.Queue()
        
    def _parse_netstat(self):
        """Parse netstat output to get active connections"""
        connections = []
        
        try:
            if is_windows:
                cmd = ["netstat", "-ano"]
            else:
                cmd = ["netstat", "-antup"]
                
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                lines = result.stdout.splitlines()
                
                # Skip header lines
                start_index = 0
                for i, line in enumerate(lines):
                    if "Proto" in line and "Local Address" in line:
                        start_index = i + 1
                        break
                
                # Process connection lines
                for line in lines[start_index:]:
                    if not line.strip():
                        continue
                        
                    parts = line.split()
                    if len(parts) < 4:
                        continue
                        
                    proto = parts[0]
                    local_addr = parts[1]
                    remote_addr = parts[2]
                    state = parts[3] if len(parts) > 3 and parts[3] != "ESTABLISHED" else "ESTABLISHED"
                    pid = parts[-1] if is_windows else "N/A"
                    
                    # Extract remote IP and port
                    if ":" in remote_addr:
                        remote_ip, remote_port = remote_addr.rsplit(":", 1)
                    else:
                        remote_ip, remote_port = remote_addr, ""
                        
                    connections.append({
                        "proto": proto,
                        "local_addr": local_addr,
                        "remote_addr": remote_addr,
                        "remote_ip": remote_ip,
                        "remote_port": remote_port,
                        "state": state,
                        "pid": pid
                    })
        except Exception as e:
            logger.error(f"Error parsing netstat output: {str(e)}")
            
        return connections
        
    def _monitor_connections(self, interval=5):
        """Background thread to monitor network connections"""
        logger.info("Network monitoring started")
        self.monitoring = True
        
        while self.monitoring:
            try:
                connections = self._parse_netstat()
                
                # Process each connection
                for conn in connections:
                    remote_ip = conn["remote_ip"]
                    remote_addr = conn["remote_addr"]
                    proto = conn["proto"]
                    pid = conn["pid"]
                    
                    # Skip local or loopback connections
                    if remote_ip in ["0.0.0.0", "127.0.0.1", "::", "::1", "*"]:
                        continue
                    
                    # Check for suspicious IPs or ports
                    suspicious = False
                    reason = ""
                    
                    if remote_ip in self.suspicious_ips:
                        suspicious = True
                        reason = f"Connection to known malicious IP: {remote_ip}"
                    elif any(domain in remote_addr for domain in self.suspicious_domains):
                        suspicious = True
                        reason = f"Connection to suspicious domain in: {remote_addr}"
                    elif conn["remote_port"] in ["4444", "31337", "1337", "666"]:  # Known exploit ports
                        suspicious = True
                        reason = f"Connection to suspicious port: {conn['remote_port']}"
                        
                    if suspicious:
                        # Get process name
                        process_name = "Unknown"
                        if pid != "N/A":
                            try:
                                process = psutil.Process(int(pid))
                                process_name = process.name()
                            except:
                                pass
                                
                        # Record the suspicious connection
                        detection_id = self.db.record_detection(
                            f"{proto} {remote_addr}", "network", reason
                        )
                        
                        self.connections_queue.put({
                            "id": detection_id,
                            "proto": proto,
                            "remote_addr": remote_addr,
                            "process_name": process_name,
                            "pid": pid,
                            "reason": reason,
                            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        })
                        
                # Wait for next check
                time.sleep(interval)
            except Exception as e:
                logger.error(f"Error in network monitoring: {str(e)}")
                time.sleep(interval)
                
        logger.info("Network monitoring stopped")
                
    def start_monitoring(self):
        """Start monitoring network connections"""
        if not self.monitoring:
            self.monitor_thread = threading.Thread(target=self._monitor_connections)
            self.monitor_thread.daemon = True
            self.monitor_thread.start()
            return True
        return False
        
    def stop_monitoring(self):
        """Stop monitoring network connections"""
        if self.monitoring:
            self.monitoring = False
            if self.monitor_thread:
                self.monitor_thread.join(timeout=1.0)
            return True
        return False
        
    def get_suspicious_connections(self):
        """Get all suspicious connections detected"""
        connections = []
        while not self.connections_queue.empty():
            connections.append(self.connections_queue.get())
        return connections
        
    def scan_current_connections(self):
        """Scan current network connections"""
        suspicious_connections = []
        
        try:
            connections = self._parse_netstat()
            
            for conn in connections:
                remote_ip = conn["remote_ip"]
                remote_addr = conn["remote_addr"]
                proto = conn["proto"]
                pid = conn["pid"]
                
                # Skip local or loopback connections
                if remote_ip in ["0.0.0.0", "127.0.0.1", "::", "::1", "*"]:
                    continue
                
                # Check for suspicious IPs or ports
                suspicious = False
                reason = ""
                
                if remote_ip in self.suspicious_ips:
                    suspicious = True
                    reason = f"Connection to known malicious IP: {remote_ip}"
                elif any(domain in remote_addr for domain in self.suspicious_domains):
                    suspicious = True
                    reason = f"Connection to suspicious domain in: {remote_addr}"
                elif conn["remote_port"] in ["4444", "31337", "1337", "666"]:  # Known exploit ports
                    suspicious = True
                    reason = f"Connection to suspicious port: {conn['remote_port']}"
                    
                if suspicious:
                    # Get process name
                    process_name = "Unknown"
                    if pid != "N/A":
                        try:
                            process = psutil.Process(int(pid))
                            process_name = process.name()
                        except:
                            pass
                            
                    # Record the suspicious connection
                    detection_id = self.db.record_detection(
                        f"{proto} {remote_addr}", "network", reason
                    )
                    
                    suspicious_connections.append({
                        "id": detection_id,
                        "proto": proto,
                        "remote_addr": remote_addr,
                        "process_name": process_name,
                        "pid": pid,
                        "reason": reason,
                        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    })
        except Exception as e:
            logger.error(f"Error scanning current connections: {str(e)}")
            
        return suspicious_connections


# Quarantine and Removal Manager
class QuarantineManager:
    def __init__(self, db, quarantine_dir="quarantine"):
        self.db = db
        self.quarantine_dir = quarantine_dir
        
        # Create quarantine directory if it doesn't exist
        if not os.path.exists(quarantine_dir):
            os.makedirs(quarantine_dir)
            
    def quarantine_file(self, file_path, detection_id):
        """Move a file to quarantine"""
        try:
            if not os.path.exists(file_path) or not os.path.isfile(file_path):
                logger.error(f"File not found for quarantine: {file_path}")
                return False
                
            # Calculate file hash
            file_hash = ""
            try:
                with open(file_path, "rb") as f:
                    file_hash = hashlib.md5(f.read()).hexdigest()
            except Exception as e:
                logger.error(f"Error calculating file hash: {str(e)}")
                
            # Generate a unique quarantine filename
            quarantine_filename = f"{file_hash}_{os.path.basename(file_path)}_{int(time.time())}.quar"
            quarantine_path = os.path.join(self.quarantine_dir, quarantine_filename)
            
            # Create quarantine metadata
            metadata = {
                "original_path": file_path,
                "detection_id": detection_id,
                "quarantine_time": datetime.datetime.now().isoformat(),
                "file_hash": file_hash
            }
            
            # Create a quarantine package (ZIP with metadata and original file)
            with zipfile.ZipFile(quarantine_path, "w", zipfile.ZIP_DEFLATED) as zf:
                # Add metadata
                zf.writestr("metadata.json", json.dumps(metadata, indent=2))
                
                # Add the original file
                zf.write(file_path, "original_file")
                
            # Record the quarantine
            self.db.record_quarantine(
                detection_id, file_path, quarantine_path, file_hash
            )
            
            # Remove the original file
            os.remove(file_path)
            
            logger.info(f"File quarantined: {file_path} -> {quarantine_path}")
            return True
            
        except Exception as e:
            logger.error(f"Error quarantining file {file_path}: {str(e)}")
            return False
            
    def restore_file(self, quarantine_id):
        """Restore a file from quarantine"""
        try:
            # Get quarantine information
            conn = sqlite3.connect(self.db.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT q.*, d.file_path, d.detection_type, d.detection_name
                FROM quarantine q
                JOIN detections d ON q.detection_id = d.id
                WHERE q.id = ?
            """, (quarantine_id,))
            
            quarantine = cursor.fetchone()
            conn.close()
            
            if not quarantine:
                logger.error(f"Quarantine ID not found: {quarantine_id}")
                return False
                
            quarantine_path = quarantine["quarantine_path"]
            original_path = quarantine["original_path"]
            
            # Extract the original file
            with tempfile.TemporaryDirectory() as temp_dir:
                with zipfile.ZipFile(quarantine_path, "r") as zf:
                    zf.extract("original_file", temp_dir)
                    
                    # Move the file back to its original location
                    original_dir = os.path.dirname(original_path)
                    if not os.path.exists(original_dir):
                        os.makedirs(original_dir)
                        
                    shutil.move(os.path.join(temp_dir, "original_file"), original_path)
                    
            logger.info(f"File restored: {quarantine_path} -> {original_path}")
            return True
            
        except Exception as e:
            logger.error(f"Error restoring file from quarantine {quarantine_id}: {str(e)}")
            return False
            
    def remove_quarantined_file(self, quarantine_id):
        """Permanently remove a quarantined file"""
        try:
            # Get quarantine information
            conn = sqlite3.connect(self.db.db_path)
            cursor = conn.cursor()
            
            cursor.execute("SELECT detection_id, quarantine_path FROM quarantine WHERE id = ?", (quarantine_id,))
            result = cursor.fetchone()
            
            if not result:
                logger.error(f"Quarantine ID not found: {quarantine_id}")
                conn.close()
                return False
                
            detection_id, quarantine_path = result
            
            # Remove the quarantine file
            if os.path.exists(quarantine_path):
                os.remove(quarantine_path)
                
            # Update database
            self.db.record_removal(detection_id)
            
            conn.close()
            logger.info(f"Quarantined file removed: {quarantine_path}")
            return True
            
        except Exception as e:
            logger.error(f"Error removing quarantined file {quarantine_id}: {str(e)}")
            return False
            
    def get_quarantined_files(self):
        """Get list of all quarantined files"""
        return self.db.get_quarantined_files()


# Main PyGuard Class
class PyGuard:
    def __init__(self, db_path="pyguard.db", quarantine_dir="quarantine"):
        self.db = Database(db_path)
        self.quarantine_manager = QuarantineManager(self.db, quarantine_dir)
        self.signature_scanner = SignatureScanner(self.db)
        self.heuristic_scanner = HeuristicScanner(self.db)
        self.process_scanner = ProcessScanner(self.db)
        self.rootkit_detector = RootkitDetector(self.db)
        self.network_monitor = NetworkMonitor(self.db)
        
    def scan_file(self, file_path):
        """Scan a single file with all detection methods"""
        results = {
            "file_path": file_path,
            "detections": []
        }
        
        # Signature-based scan
        sig_result = self.signature_scanner.scan_file(file_path)
        if sig_result:
            results["detections"].append(sig_result)
            
        # Heuristic scan
        heur_result = self.heuristic_scanner.scan_file(file_path)
        if heur_result:
            results["detections"].append(heur_result)
            
        return results
        
    def scan_directory(self, directory, recursive=True):
        """Scan a directory with all detection methods"""
        results = {
            "directory": directory,
            "signature_detections": [],
            "heuristic_detections": []
        }
        
        # Signature-based scan
        sig_detections = self.signature_scanner.scan_directory(directory, recursive)
        results["signature_detections"] = sig_detections
        
        # Heuristic scan
        heur_detections = self.heuristic_scanner.scan_directory(directory, recursive)
        results["heuristic_detections"] = heur_detections
        
        return results
        
    def scan_system(self):
        """Perform a full system scan"""
        results = {
            "file_scans": {},
            "process_scan": None,
            "rootkit_scan": None,
            "network_scan": None
        }
        
        # Scan system directories
        system_dirs = []
        if is_windows:
            system_dirs = [
                os.environ.get("SystemRoot", "C:\\Windows"),
                os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "System32"),
                os.environ.get("ProgramFiles", "C:\\Program Files"),
                os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)"),
                os.environ.get("TEMP", "C:\\Windows\\Temp"),
                os.environ.get("APPDATA", os.path.expanduser("~\\AppData\\Roaming"))
            ]
        else:
            system_dirs = [
                "/bin", 
                "/usr/bin", 
                "/sbin", 
                "/usr/sbin",
                "/tmp", 
                os.path.expanduser("~")
            ]
            
        for directory in system_dirs:
            if os.path.exists(directory) and os.path.isdir(directory):
                results["file_scans"][directory] = self.scan_directory(directory, recursive=True)
                
        # Process and autorun scan
        results["process_scan"] = self.process_scanner.scan()
        
        # Rootkit scan
        results["rootkit_scan"] = self.rootkit_detector.scan()
        
        # Network scan
        results["network_scan"] = self.network_monitor.scan_current_connections()
        
        return results
        
    def quarantine_file(self, file_path, detection_id):
        """Quarantine a file"""
        return self.quarantine_manager.quarantine_file(file_path, detection_id)
        
    def restore_file(self, quarantine_id):
        """Restore a file from quarantine"""
        return self.quarantine_manager.restore_file(quarantine_id)
        
    def remove_file(self, quarantine_id):
        """Permanently remove a quarantined file"""
        return self.quarantine_manager.remove_quarantined_file(quarantine_id)
        
    def get_quarantined_files(self):
        """Get list of quarantined files"""
        return self.quarantine_manager.get_quarantined_files()
        
    def start_network_monitoring(self):
        """Start monitoring network connections"""
        return self.network_monitor.start_monitoring()
        
    def stop_network_monitoring(self):
        """Stop monitoring network connections"""
        return self.network_monitor.stop_monitoring()
        
    def get_suspicious_connections(self):
        """Get suspicious network connections"""
        return self.network_monitor.get_suspicious_connections()


# Command-line interface
def parse_args():
    parser = argparse.ArgumentParser(description="PyGuard: Malware Detection and Removal Tool")
    
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")
    
    # Scan commands
    scan_parser = subparsers.add_parser("scan", help="Scan for malware")
    scan_parser.add_argument("--file", "-f", help="Scan a specific file")
    scan_parser.add_argument("--dir", "-d", help="Scan a directory")
    scan_parser.add_argument("--recursive", "-r", action="store_true", help="Recursively scan directories")
    scan_parser.add_argument("--system", "-s", action="store_true", help="Perform a full system scan")
    scan_parser.add_argument("--processes", "-p", action="store_true", help="Scan running processes")
    scan_parser.add_argument("--rootkit", "-k", action="store_true", help="Scan for rootkits")
    scan_parser.add_argument("--network", "-n", action="store_true", help="Scan network connections")
    
    # Quarantine commands
    quarantine_parser = subparsers.add_parser("quarantine", help="Manage quarantined files")
    quarantine_parser.add_argument("--list", "-l", action="store_true", help="List quarantined files")
    quarantine_parser.add_argument("--quarantine", "-q", help="Quarantine a file")
    quarantine_parser.add_argument("--restore", "-r", type=int, help="Restore a file from quarantine by ID")
    quarantine_parser.add_argument("--remove", "-x", type=int, help="Permanently remove a quarantined file by ID")
    
    # Network monitor commands
    network_parser = subparsers.add_parser("network", help="Network monitoring")
    network_parser.add_argument("--start", "-s", action="store_true", help="Start network monitoring")
    network_parser.add_argument("--stop", "-t", action="store_true", help="Stop network monitoring")
    network_parser.add_argument("--list", "-l", action="store_true", help="List suspicious connections")
    
    return parser.parse_args()


def main():
    """Main function"""
    args = parse_args()
    pyguard = PyGuard()
    
    # Handle scan commands
    if args.command == "scan":
        if args.file:
            # Scan a specific file
            print(f"\nScanning file: {args.file}")
            result = pyguard.scan_file(args.file)
            
            if result["detections"]:
                print(f"\n[!] Malware detected in {args.file}:")
                for detection in result["detections"]:
                    print(f"  - {detection['name']} (ID: {detection['id']})")
                    print(f"    Type: {detection['type']}")
                    if "score" in detection:
                        print(f"    Score: {detection['score']}")
                        print(f"    Reasons: {', '.join(detection['reasons'])}")
                print("\nUse 'pyguard quarantine --quarantine ID' to quarantine the file")
            else:
                print(f"\n[✓] No threats detected in {args.file}")
        
        elif args.dir:
            # Scan a directory
            print(f"\nScanning directory: {args.dir}")
            result = pyguard.scan_directory(args.dir, args.recursive)
            
            sig_detections = result["signature_detections"]
            heur_detections = result["heuristic_detections"]
            
            if sig_detections or heur_detections:
                print(f"\n[!] Malware detected in {args.dir}:")
                
                if sig_detections:
                    print("\nSignature-based detections:")
                    for file_path, detection in sig_detections:
                        print(f"  - {file_path}")
                        print(f"    Detection: {detection['name']} (ID: {detection['id']})")
                        print(f"    Type: {detection['type']}")
                        
                if heur_detections:
                    print("\nHeuristic detections:")
                    for file_path, detection in heur_detections:
                        print(f"  - {file_path}")
                        print(f"    Detection: {detection['name']} (ID: {detection['id']})")
                        print(f"    Score: {detection['score']}")
                        print(f"    Reasons: {', '.join(detection['reasons'])}")
                        
                print("\nUse 'pyguard quarantine --quarantine ID' to quarantine detected files")
            else:
                print(f"\n[✓] No threats detected in {args.dir}")
                
        elif args.processes:
            # Scan running processes
            print("\nScanning running processes...")
            result = pyguard.process_scanner.scan()
            
            if result["processes"]:
                print("\n[!] Suspicious processes detected:")
                for proc in result["processes"]:
                    print(f"  - {proc['name']} (PID: {proc['pid']})")
                    print(f"    Path: {proc['path']}")
                    print(f"    Reason: {proc['reason']}")
                    print(f"    Detection ID: {proc['id']}")
                    
            else:
                print("\n[✓] No suspicious processes detected")
                
            if result["autoruns"]:
                print("\n[!] Suspicious autorun entries detected:")
                for autorun in result["autoruns"]:
                    print(f"  - {autorun['name']}")
                    print(f"    Source: {autorun['source']}")
                    print(f"    Command: {autorun['command']}")
                    print(f"    Reason: {autorun['reason']}")
            else:
                print("\n[✓] No suspicious autorun entries detected")
                
        elif args.rootkit:
            # Scan for rootkits
            print("\nScanning for rootkits...")
            result = pyguard.rootkit_detector.scan()
            
            if result["hidden_files"]:
                print("\n[!] Hidden files detected (possible rootkit):")
                for file in result["hidden_files"]:
                    print(f"  - {file['path']}")
                    print(f"    Type: {file['type']}")
                    print(f"    Reason: {file['reason']}")
                    print(f"    Detection ID: {file['id']}")
            else:
                print("\n[✓] No hidden files detected")
                
            if result["syscall_hooks"]:
                print("\n[!] Potential syscall hooks detected:")
                for hook in result["syscall_hooks"]:
                    if "process" in hook:
                        print(f"  - Process: {hook['process']} (PID: {hook['process_id']})")
                        print(f"    Module: {hook['module']}")
                    else:
                        print(f"  - Module: {hook['module']}")
                    print(f"    Reason: {hook['reason']}")
                    print(f"    Detection ID: {hook['id']}")
            else:
                print("\n[✓] No syscall hooks detected")
                
        elif args.network:
            # Scan network connections
            print("\nScanning network connections...")
            result = pyguard.network_monitor.scan_current_connections()
            
            if result:
                print("\n[!] Suspicious network connections detected:")
                for conn in result:
                    print(f"  - {conn['proto']} {conn['remote_addr']}")
                    print(f"    Process: {conn['process_name']} (PID: {conn['pid']})")
                    print(f"    Reason: {conn['reason']}")
                    print(f"    Detection ID: {conn['id']}")
            else:
                print("\n[✓] No suspicious network connections detected")
                
        elif args.system:
            # Perform a full system scan
            print("\nPerforming full system scan. This may take a while...")
            result = pyguard.scan_system()
            
            # Display results
            print("\n=== PyGuard System Scan Results ===")
            
            # File scan results
            has_file_detections = False
            for directory, scan_result in result["file_scans"].items():
                sig_detections = scan_result["signature_detections"]
                heur_detections = scan_result["heuristic_detections"]
                
                if sig_detections or heur_detections:
                    has_file_detections = True
                    print(f"\n[!] Malware detected in {directory}:")
                    
                    if sig_detections:
                        print("\nSignature-based detections:")
                        for file_path, detection in sig_detections:
                            print(f"  - {file_path}")
                            print(f"    Detection: {detection['name']} (ID: {detection['id']})")
                            
                    if heur_detections:
                        print("\nHeuristic detections:")
                        for file_path, detection in heur_detections:
                            print(f"  - {file_path}")
                            print(f"    Detection: {detection['name']} (ID: {detection['id']})")
                            print(f"    Score: {detection['score']}")
                            
            if not has_file_detections:
                print("\n[✓] No file-based threats detected")
                
            # Process scan results
            process_results = result["process_scan"]
            if process_results["processes"]:
                print("\n[!] Suspicious processes detected:")
                for proc in process_results["processes"]:
                    print(f"  - {proc['name']} (PID: {proc['pid']})")
                    print(f"    Reason: {proc['reason']}")
            else:
                print("\n[✓] No suspicious processes detected")
                
            if process_results["autoruns"]:
                print("\n[!] Suspicious autorun entries detected:")
                for autorun in process_results["autoruns"]:
                    print(f"  - {autorun['name']}")
                    print(f"    Source: {autorun['source']}")
            else:
                print("\n[✓] No suspicious autorun entries detected")
                
            # Rootkit scan results
            rootkit_results = result["rootkit_scan"]
            if rootkit_results["hidden_files"] or rootkit_results["syscall_hooks"]:
                print("\n[!] Potential rootkit detected:")
                
                if rootkit_results["hidden_files"]:
                    print("\nHidden files:")
                    for file in rootkit_results["hidden_files"]:
                        print(f"  - {file['path']}")
                        print(f"    Reason: {file['reason']}")
                        
                if rootkit_results["syscall_hooks"]:
                    print("\nSyscall hooks:")
                    for hook in rootkit_results["syscall_hooks"]:
                        if "process" in hook:
                            print(f"  - Process: {hook['process']}")
                        else:
                            print(f"  - Module: {hook['module']}")
                        print(f"    Reason: {hook['reason']}")
            else:
                print("\n[✓] No rootkits detected")
                
            # Network scan results
            network_results = result["network_scan"]
            if network_results:
                print("\n[!] Suspicious network connections detected:")
                for conn in network_results:
                    print(f"  - {conn['proto']} {conn['remote_addr']}")
                    print(f"    Process: {conn['process_name']}")
                    print(f"    Reason: {conn['reason']}")
            else:
                print("\n[✓] No suspicious network connections detected")
                
            print("\n=== Scan Complete ===")
            print("\nIMPORTANT: If any malware was detected, especially keyloggers or rootkits,")
            print("it is recommended that you change all your passwords after cleaning your system.")
            print("Use 'pyguard quarantine --list' to see detected threats")
            print("Use 'pyguard quarantine --quarantine ID' to quarantine detected files")
            
        else:
            print("Error: No scan type specified. Use --file, --dir, --system, --processes, --rootkit, or --network")
            
    # Handle quarantine commands
    elif args.command == "quarantine":
        if args.list:
            # List quarantined files
            quarantined = pyguard.get_quarantined_files()
            
            if quarantined:
                print("\nQuarantined files:")
                for item in quarantined:
                    print(f"  ID: {item['id']}")
                    print(f"  Original path: {item['file_path']}")
                    print(f"  Detection: {item['detection_name']}")
                    print(f"  Quarantined at: {item['quarantine_time']}")
                    print()
                    
                print("\nUse 'pyguard quarantine --restore ID' to restore a file")
                print("Use 'pyguard quarantine --remove ID' to permanently delete a file")
            else:
                print("\nNo files in quarantine")
                
        elif args.quarantine:
            # Quarantine a file by detection ID
            try:
                detection_id = int(args.quarantine)
                
                # Get detection information
                conn = sqlite3.connect(pyguard.db.db_path)
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                cursor.execute("SELECT file_path FROM detections WHERE id = ?", (detection_id,))
                detection = cursor.fetchone()
                conn.close()
                
                if not detection:
                    print(f"\nError: Detection ID {detection_id} not found")
                else:
                    file_path = detection["file_path"]
                    if pyguard.quarantine_file(file_path, detection_id):
                        print(f"\n[✓] File successfully quarantined: {file_path}")
                    else:
                        print(f"\n[✗] Failed to quarantine file: {file_path}")
            except ValueError:
                print("\nError: Invalid detection ID")
                
        elif args.restore:
            # Restore a file from quarantine
            quarantine_id = args.restore
            
            if pyguard.restore_file(quarantine_id):
                print(f"\n[✓] File with ID {quarantine_id} successfully restored")
            else:
                print(f"\n[✗] Failed to restore file with ID {quarantine_id}")
                
        elif args.remove:
            # Permanently remove a quarantined file
            quarantine_id = args.remove
            
            if pyguard.remove_file(quarantine_id):
                print(f"\n[✓] File with ID {quarantine_id} permanently removed")
            else:
                print(f"\n[✗] Failed to remove file with ID {quarantine_id}")
                
        else:
            print("Error: No quarantine action specified. Use --list, --quarantine, --restore, or --remove")
            
    # Handle network monitor commands
    elif args.command == "network":
        if args.start:
            # Start network monitoring
            if pyguard.start_network_monitoring():
                print("\n[✓] Network monitoring started")
                print("Use 'pyguard network --list' to view detected suspicious connections")
                print("Use 'pyguard network --stop' to stop monitoring")
            else:
                print("\n[✗] Network monitoring is already running")
                
        elif args.stop:
            # Stop network monitoring
            if pyguard.stop_network_monitoring():
                print("\n[✓] Network monitoring stopped")
            else:
                print("\n[✗] Network monitoring is not running")
                
        elif args.list:
            # List suspicious connections
            connections = pyguard.get_suspicious_connections()
            
            if connections:
                print("\nSuspicious network connections:")
                for conn in connections:
                    print(f"  - {conn['proto']} {conn['remote_addr']}")
                    print(f"    Process: {conn['process_name']} (PID: {conn['pid']})")
                    print(f"    Reason: {conn['reason']}")
                    print(f"    Time: {conn['timestamp']}")
                    print(f"    Detection ID: {conn['id']}")
                    print()
            else:
                print("\nNo suspicious network connections detected")
                
        else:
            print("Error: No network monitor action specified. Use --start, --stop, or --list")
            
    else:
        print("Error: No command specified. Use 'scan', 'quarantine', or 'network'")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
    except Exception as e:
        logger.error(f"Unhandled exception: {str(e)}")
        print(f"\nError: {str(e)}")
        print("See the log file for more details")


# Example usage instructions
"""
PyGuard: Malware Detection and Removal Tool

1. Scanning for malware:
   - Scan a file: python pyguard.py scan --file suspicious_file.exe
   - Scan a directory: python pyguard.py scan --dir C:\Downloads
   - Scan a directory recursively: python pyguard.py scan --dir C:\Downloads --recursive
   - Scan running processes: python pyguard.py scan --processes
   - Scan for rootkits: python pyguard.py scan --rootkit
   - Scan network connections: python pyguard.py scan --network
   - Full system scan: python pyguard.py scan --system

2. Managing quarantined files:
   - List quarantined files: python pyguard.py quarantine --list
   - Quarantine a detected file: python pyguard.py quarantine --quarantine DETECTION_ID
   - Restore a file from quarantine: python pyguard.py quarantine --restore QUARANTINE_ID
   - Permanently remove a file: python pyguard.py quarantine --remove QUARANTINE_ID

3. Network monitoring:
   - Start monitoring: python pyguard.py network --start
   - Stop monitoring: python pyguard.py network --stop
   - List suspicious connections: python pyguard.py network --list

For help: python pyguard.py --help
"""
