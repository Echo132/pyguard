# PyGuard: Malware Detection and Removal Tool

![Malware Detection](https://img.shields.io/badge/Security-Malware%20Detection-brightgreen)
![Python](https://img.shields.io/badge/Language-Python-blue)
![License](https://img.shields.io/badge/License-MIT-yellow)

PyGuard is a comprehensive malware detection and removal tool designed to protect systems from a variety of malware threats. This project combines multiple detection methods with quarantine and removal capabilities to provide robust security protection.

by joey russell

personal notes 

I want to make a script that could cover a wide scope, but biting more than I could handle, I was forced to use AI to help with my structure, but this let me be more creative in my approach. 

## Features

there are some bugs i am still working on :)

### 1. Signature-based Detection
- Scans files using MD5 hash comparison
- Detects known malware patterns in file headers
- Uses regex pattern matching for identifying suspicious code

### 2. Heuristic Analysis
- Evaluates files based on suspicious characteristics
- Scores files against known malicious behaviors
- Detects potentially harmful files that evade signature-based detection

### 3. Process & Autorun Scanner
- Identifies suspicious running processes
- Detects system process imitations
- Scans autorun entries in registry and startup folders
- Finds unauthorized system modifications

### 4. Rootkit Detection
- Discovers files hidden with rootkit techniques
- Detects API discrepancies that indicate rootkit presence
- Identifies alternate data streams on Windows systems

### 5. Quarantine System
- Safely isolates detected threats
- Maintains detailed database of quarantined files
- Provides options for removal or restoration

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/pyguard.git
cd pyguard

# Install required dependencies
pip install -r requirements.txt
```

## Requirements

- Python 3.6+
- Windows: pywin32 (for advanced Windows-specific features)
- psutil (for process scanning)
- Additional dependencies listed in requirements.txt

## Usage

```bash
# Basic scan of a directory
python pyguard.py --scan /path/to/directory

# Full system scan with all detection methods
python pyguard.py --full-scan

# Scan processes and autoruns
python pyguard.py --scan-processes

# List quarantined files
python pyguard.py --list-quarantine

# Restore a file from quarantine
python pyguard.py --restore-file <file_id>

# Remove a quarantined file permanently
python pyguard.py --remove-file <file_id>
```

## Development Challenges

During the development of PyGuard, I faced several challenges:

1. **Cross-Platform Compatibility**: 
   - Implementing rootkit detection across different operating systems proved difficult
   - Windows-specific features required conditional coding and alternative approaches for Unix/Linux

2. **False Positives**:
   - Balancing detection sensitivity with false positive rates
   - Heuristic analysis sometimes flagged legitimate software as suspicious
   - Required fine-tuning of detection thresholds

3. **Privilege Limitations**:
   - Some scanning features require administrator/root access
   - Implemented graceful degradation when running with limited privileges

4. **Performance Optimization**:
   - Full system scans were initially very slow
   - Had to implement multi-threading and optimize file reading operations
   - Balancing thoroughness with reasonable scan times

5. **Evasive Malware**:
   - Modern malware uses various techniques to avoid detection
   - Implemented multiple detection methods to mitigate this
   - Still struggling with highly polymorphic malware

## Future Improvements

- Implement cloud-based signature updates
- Add behavioral analysis through sandboxing
- Improve the user interface with real-time scan statistics
- Add network traffic monitoring
- Create a scheduling system for automated scans

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Project completed as part of Malware Removal Project (Due Date: 4/25)
- Inspired by industry-standard malware detection techniques
- Thanks to all contributors and testers
