# DNS Enumeration Tool (dns_enum.sh)
## Author

Developed and maintained by **Debug**.
```
================================================================
                  dns_enum.sh — DNS Enumeration Tool
================================================================
```

## Requirements

Install the required packages:

```bash
sudo apt install dnsutils nmap
```

## Usage

Make the script executable:

```bash
chmod +x dns_enum.sh
```

Run the script:

```bash
sudo ./dns_enum.sh <TARGET_IP>
```

Example:

```bash
sudo ./dns_enum.sh 10.129.14.128
```

---

## Domain Prompt

When the script starts, it will ask for the target domain.

- **If you know the domain**, enter it (e.g. `inlanefreight.htb`)
- **If you don't know it**, simply press **Enter** and the script will attempt a reverse DNS (PTR) lookup automatically.

---

# Enumeration Features

The script performs the following DNS enumeration tasks:

- Automatically updates `/etc/hosts` with the discovered IP and domain
- **NS Records** (Nameservers + their IP addresses)
- **MX Records** (Mail servers)
- **TXT Records**
  - SPF
  - DMARC
  - DKIM
  - Domain verification records
- **A / AAAA Records**
- **SOA Record**
  - Administrator email
  - Serial number
  - TTL
- **ANY Query**
- **CNAME Records**
- **SRV Records**
  - LDAP
  - Kerberos
  - HTTP
  - SIP
  - SSH
  - and other common services
- **PTR Lookups** for every discovered IP
- **Wildcard DNS Detection**
- **AXFR Zone Transfer** against every discovered nameserver
- **DNSSEC / NSEC Detection**
  - Checks whether zone walking is possible
- **Common Subdomain Enumeration**
  - Uses approximately 50 common subdomain names for quick wins
- **CHAOS Fingerprinting**
  - `version.bind`
  - `hostname.bind`
- **Zone Transfer**
  - Attempts AXFR directly against the supplied DNS server IP

---

# Subdomain Brute Force

After the initial enumeration, the script asks:

```
Run subdomain brute-force? (y/n)
```

If you answer **yes**, you may provide a custom wordlist or simply press **Enter** to use the default SecLists wordlist.

## Recommended Wordlists

Fast

```
/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

Medium

```
/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt
```

Large

```
/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
```

HTB Academy

```
/opt/useful/seclists/Discovery/DNS/subdomains-top1million-110000.txt
```

---

## After Brute Force

Once brute forcing finishes, the script offers three optional actions:

1. Re-enumerate every discovered subdomain
   - DNS records
   - Zone transfer
   - Additional DNS information

2. Run a mutation attack against every discovered subdomain

3. Run a deep brute-force on every discovered subdomain

---

# Mutation Attack

When a subdomain is discovered (for example):

```
ns.domain.htb
```

The script automatically generates common variations such as:

```
ns1.domain.htb
ns2.domain.htb
...
ns20.domain.htb
```

It also tries patterns like:

```
ns-word.domain.htb
word-ns.domain.htb
```

This approach is significantly faster than performing another full recursive brute-force while still discovering many additional hosts.

---

# Output

Results are saved automatically.

```
dns_results/
├── dns_<domain>_<timestamp>.txt
└── subdomains_<domain>_<timestamp>.txt
```

- **dns_*** contains the complete enumeration report.
- **subdomains_*** contains the discovered subdomains only.

---

# OSCP Notes

- Uses only **dig** and **nmap**.
- Designed to comply with **OSCP exam** restrictions.
- Always perform an **Nmap scan first** to confirm that TCP/UDP port **53** is open.
- Enumeration reports are generated automatically for documentation.

---

# Disclaimer

This tool is intended for authorized security assessments, penetration testing, and educational purposes only. Use it only against systems for which you have explicit permission.
