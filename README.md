# Intelligent Machine Discovery
[![version](https://img.shields.io/badge/version-1.0.0-blue.svg)](https://github.com/kmanc/intelligent_machine_discovery/releases/tag/1.0.0)
[![GPLv3 license](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0.txt)


## Intro
IMD is an executable made to do remote discovery / recon on machines like you might find in CTFs.
It is the evolution of a shell script I wrote for my [OSCP exam](https://www.offensive-security.com/pwk-oscp/) that I decided to make in Rust as a learning experience, and for use in CTFs like those on [HackTheBox](https://www.hackthebox.eu/).


## Features
- organization of all relevant data in a directory for the target machine
- nmap scan on common ports with service discovery
- nmap scan on all TCP ports
- showmount scan for NFS shares
- threaded where possible to improve runtime
- _If applicable_ addition of hostname to /etc/hosts
- _If applicable_ nikto scan on ports hosting websites
- _If applicable_ gobuster directory scan on ports hosting websites
- _If applicable_ wfuzz file scan on all directories found on ports hosting websites


## Setup
1. Download the most recent release from the [release page](https://github.com/kmanc/intelligent_machine_discovery/releases/)
2. Move imd to whichever directory you normally work out of
3. Give imd execute rights (run `chmod +x imd`)
4. Make sure you have all [dependencies listed below](#-dependencies)

## How to use

```
sudo ./imd <ip_address> [<hostname> [<ip_address> [<hostname]]]
```

#### Examples

```
sudo ./imd 10.10.10.215

sudo ./imd 10.10.10.215 academy.htb

sudo ./imd 10.10.10.215 10.10.10.216 10.10.10.217

sudo ./imd 10.10.10.215 academy.htb 10.10.10.216 10.10.10.217 cereal.htb 10.10.10.218 10.10.10.219
```


## <a name="dependencies"></a> Dependencies
In order to run early versions of IMD you will need a few things on your machine that you may not have already
- [Nmap](https://nmap.org/)
- [Nikto](https://cirt.net/Nikto2)
- [Gobuster](https://github.com/OJ/gobuster)
- [Wfuzz](https://github.com/xmendez/wfuzz)
- The following files (in the following places)
    - [/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt](https://github.com/daviddias/node-dirbuster/blob/master/lists/directory-list-2.3-small.txt)
    - [/usr/share/wordlists/seclists/raft-medium-files.txt](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/raft-medium-files.txt)


## TODO
- Bugfixes
    - As they are found / reported
- Configurable options
    - Users can choose whether or not to run nikto
    - Users can choose how long to let each nikto task to run before stopping it short
    - Users can choose their favorite web directory scanner (defaults to gobuster)
    - Users can choose their favorite web file scanner (defaults to wfuzz)
    - Users can specify their wordlist(s) of choice for web directories and files respectively
- FTP scanning
    - Check for anonymous access if FTP is found
- Stdout reporting
    - Live updates that you can read (even with thread context making this confusing)
    - Point out things of interest as they are found
- "TLDR" output
    - Basically a quick reference of highlights when all scans are done
- Code cleanup / best practices / efficiency
    - Still learning a lot of this stuff so it's not pretty
- Other
    - This was a first pass at discovery; there's always more to learn/add
