# Intelligent Machine Discovery
[![version](https://img.shields.io/badge/version-1.2.1-blue.svg)](https://github.com/kmanc/intelligent_machine_discovery/releases/tag/1.2.0)
[![license](https://img.shields.io/github/license/kmanc/intelligent_machine_discovery?style=flat&color=blueviolet)](https://raw.githubusercontent.com/kmanc/intelligent_machine_discovery/main/LICENSE)


## Intro
IMD is an executable made to do remote discovery / recon on machines like you might find in CTFs.
It is the evolution of a shell script I wrote for my [OSCP exam](https://www.offensive-security.com/pwk-oscp/) that I decided to make in Rust as a learning experience, and for use in CTFs like those on [HackTheBox](https://www.hackthebox.eu/).


## Features
- organization of all relevant data in a directory for the target machine
- Common TCP port scan with service discovery
- Full TCP port scan
- Detection of NFS shares
- _If applicable_ addition of hostname to /etc/hosts
- _If applicable_ nikto scan on ports hosting websites
- _If applicable_ feroxbuster scan for ports hosting websites


## Setup
1. Download the most recent release from the [release page](https://github.com/kmanc/intelligent_machine_discovery/releases/)
2. Give imd execute rights (run `chmod +x imd`)
3. Move imd to `usr/local/bin`
4. Ensure that you have the required dependencies:
    1. [feroxbuster](https://github.com/epi052/feroxbuster) installed
    2. [nikto](https://cirt.net/Nikto2) installed
    3. [nmap](https://nmap.org/) installed
    4. [showmount](https://linux.die.net/man/8/showmount) installed
    4. [raft-medium-directories.txt](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/raft-medium-directories.txt) file in `/usr/share/wordlists/seclists/`

![setup](https://user-images.githubusercontent.com/14863147/184455461-5726cad6-be82-4cdd-a09d-b818bf33e4f5.gif)


## Use

```
sudo imd <ip_address> [<hostname> [<ip_address> [<hostname]]]
```

![imd](https://user-images.githubusercontent.com/14863147/184455658-29795986-c67f-432f-84bb-967e70f761e7.gif)


Once the scans complete, you can look through the output in the resulting folders


![output](https://user-images.githubusercontent.com/14863147/184455694-7db66537-bb20-4f92-b52e-d61aa7fe61aa.gif)


#### Examples

```
sudo ./imd 10.10.10.215

sudo ./imd 10.10.10.215 academy.htb

sudo ./imd 10.10.10.215 10.10.10.216 10.10.10.217

sudo ./imd 10.10.10.215 academy.htb 10.10.10.216 10.10.10.217 cereal.htb 10.10.10.218 10.10.10.219
```

