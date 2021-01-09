# Intelligent Machine Discovery

This is a poor excuse for a real README, but a "real" README is in the works. IMD is a tool made to do discovery/recon on machines like you might find in CTFs.
It is the evolution of a shell script I wrote for my OSCP exam that I decided to make in Rust as a learning experience.

USE:

`sudo ./imd <ip_address> [<hostname> [<ip_address> [<hostname]]]`

EXAMPLES:

`sudo ./imd 10.10.10.215`

`sudo ./imd 10.10.10.215 academy.htb`

`sudo ./imd 10.10.10.215 10.10.10.216 10.10.10.217`

`sudo ./imd 10.10.10.215 academy.htb 10.10.10.216 10.10.10.217 cereal.htb`

NOTE: In order to run early versions of IMD you will need a few things on your machine that you may not have already
- [Nmap](https://nmap.org/)
- [Nikto](https://cirt.net/Nikto2)
- [Gobuster](https://github.com/OJ/gobuster)
- [Wfuzz](https://github.com/xmendez/wfuzz)
- The following files (in the following places)
    - [/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt](https://github.com/daviddias/node-dirbuster/blob/master/lists/directory-list-2.3-small.txt)
    - [/usr/share/wordlists/seclists/raft-medium-files.txt](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/raft-medium-files.txt)

#### TODO
- Bugfixes
    - There is bound to be a few
- Offer options
    - There are lots of hard-coded things that can't be changed in v0.1.0
- A better README
    - Plans for the future
    - How to interpret results
- FTP scanning
    - Check for anonymous access
- Other
    - This was a first pass at discovery; there's always more to learn/add
- Live reporting
    - Consistent "live updates"
    - Point out things of interest
    - Colorize high interest text?
- "TLDR" output
    - Basically a quick reference of highlights
- Code cleanup
    - Still learning a lot of this stuff so it's not pretty
