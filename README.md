# NetworkAlarm
A command-line tool to monitor local network traffic for possible security vulnerabilities. Warns user against possible nmap scans, Nikto scans, credentials sent in-the-clear, and shellshock attacks. Currently supports live monitoring and network capture (pcap) scanning. Built as part of the Computer System Security class at Tufts University.


#### Vulnerability Monitoring
- nmap scans
	- Protects against NULL, FYN, and XMAS stealth attacks
	- Note: DOES NOT protect against non-stealthy scans, check server logs for possible scans
- Nikto scans
	- Checks for packets signed by Nikto–it's a *very* noisy tool
- Shellshock (bashdoor)
	- Scans packets attempting to exploit the shellshock vulnerability (CVE-2014-6271)
	- Checks for common configurations of the shellshock attack in incoming packets
- Credentials sent in-the-clear
	- Checks for known and popular username/password identifiers to check for possible credentials
	- Decodes base64 encoded strings for monitoring
	- Matches username and password in case sent/received across multiple packets

#### Running
```
alarm.py [-h] [-i INTERFACE] [-r PCAPFILE]
```

Use `-h` for more info.


------------------------------------------------
Check `requirements.txt` for required libraries.