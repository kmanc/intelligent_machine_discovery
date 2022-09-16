---
title: "Intelligent Machine Discovery"
---

# Intelligent Machine Discovery
[![Custom Badge](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fkmanc%2Fintelligent_machine_discovery%2Fmain%2F.custom_shields%2Fimd.json)](https://github.com/kmanc/intelligent_machine_discovery/releases/)
[![license](https://img.shields.io/github/license/kmanc/intelligent_machine_discovery?style=flat&color=blueviolet)](https://raw.githubusercontent.com/kmanc/intelligent_machine_discovery/main/LICENSE)


## Intro
IMD is an executable made to do remote discovery / recon on machines like you might find in CTFs.
It is the evolution of a shell script I wrote for my [OSCP exam](https://www.offensive-security.com/pwk-oscp/) that I decided to make in Rust as a learning experience, and for use in CTFs like those on [HackTheBox](https://www.hackthebox.eu/).


## Features
- Common TCP port scan with service discovery
- Full TCP port scan
- Detection of NFS shares
- Organization of all relevant data in a directory for the target machine
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

![setup](https://user-images.githubusercontent.com/14863147/184455461-5726cad6-be82-4cdd-a09d-b818bf33e4f5.gif)


## Use

```
sudo imd -t IP_ADDRESS_1 IP_ADDRESS_2 ... -n HOSTNAME_1 HOSTNAME_2 ... -w WORDLIST
```


![imd](https://user-images.githubusercontent.com/14863147/184567581-588a5226-7814-438e-9884-4b1252c9cd0c.gif)


As individual scans complete, you'll be able to view their output in their respective directory and file


![output](https://user-images.githubusercontent.com/14863147/184512939-ca29f562-d2dc-483c-9147-345e33174294.gif)


#### Examples

```
sudo imd -t 10.10.10.215
```

```
sudo imd -t 10.10.10.215 -n academy.htb
```

```
sudo imd -t 10.10.10.215 10.10.10.216 10.10.10.217
```

```
sudo imd -t 10.10.10.215 10.10.10.217 10.10.10.216 10.10.10.218 10.10.10.219 -n academy.htb cereal.htb 
```

```
sudo imd -t 10.10.10.215 -w /usr/share/wordlists/dirbuster/directory-list-lowercase-small.txt
```
