# ApacheHunter - Advanced Apache Server Scanner

**Developed by Rownok Ahmed Khan**  
**GitHub: [https://github.com/Rk-000](https://github.com/Rk-000)**

ApacheHunter is a powerful scanner designed to detect Apache servers, identify versions, and check for CVE-2024-22393 (Pixel Flood vulnerability) in Apache Answer installations.

## Features
- ✅ Detect Apache servers and extract versions
- ✅ Check for CVE-2024-22393 vulnerability
- ✅ Multiple detection methods (headers, page analysis, path probing)
- ✅ Three scanning speeds (slow, normal, fast)
- ✅ Proxy support
- ✅ Multiple output formats (TXT, JSON, CSV)
- ✅ Multi-threading support
- ✅ Colorized terminal output
- ✅ Confidence scoring

## Installation

```bash
# Clone the repository
git clone https://github.com/Rk-000/ApacheHunter.git
cd ApacheHunter

# Install dependencies
pip install -r requirements.txt

# Make the script executable
chmod +x ApacheHunter.py


Basic Scanning
# Scan single URL
python ApacheHunter.py -u example.com

# Scan multiple targets from file
python ApacheHunter.py -f targets.txt

# Scan with output
python ApacheHunter.py -f targets.txt -o scan_results --format json

# Run scan with delay (for accuracy)
python ApacheHunter.py -f targets.txt --delay 2

# Or run fast but accurate
python ApacheHunter.py -f targets.txt --delay 1

Advanced Options
# Specify detection method
python ApacheHunter.py -u example.com --method headers

# Control scan speed
python ApacheHunter.py -f targets.txt --speed slow --delay 1

# Use proxy
python ApacheHunter.py -u example.com --proxy http://127.0.0.1:8080

# Multi-threaded scanning
python ApacheHunter.py -f targets.txt --speed fast --threads 20

# Custom User-Agent
python ApacheHunter.py -u example.com --user-agent "Mozilla/5.0..."


Help
python ApacheHunter.py -h


TXT Output
python ApacheHunter.py -f targets.txt -o results --format txt

JSON Output
python ApacheHunter.py -f targets.txt -o results --format json

CSV Output
python ApacheHunter.py -f targets.txt -o results --format csv