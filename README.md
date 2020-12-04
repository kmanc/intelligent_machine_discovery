# Intelligent Machine Discovery

This is a poor excuse for a real README, but a "real" README is in the works. IMD is a tool made to do discovery/recon on machines like you might find in CTFs.
It is the evolution of a shell script I wrote for my OSCP exam that I decided to make in Rust as a learning experience.

USE:

`./imd <ip_address> [-h <hostname>]`

EXAMPLE:

`./imd 10.10.10.215 academy.htb`

NOTE: In order to run early versions of IMD you will need a few things on your machine that you may not have already
- [Nmap](https://nmap.org/)
- [Nikto](https://cirt.net/Nikto2)
- [Gobuster](https://github.com/OJ/gobuster)
- [Wfuzz](https://github.com/xmendez/wfuzz)
- The following files (in the following places)
    - [/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt](https://github.com/daviddias/node-dirbuster/blob/master/lists/directory-list-2.3-small.txt)
    - [/usr/share/wordlists/seclists/raft-medium-files.txt](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/raft-medium-files.txt)

#### TODO
- General code cleanup
    - Most of v1 is hacked together to get it to work. It's not pretty (yet)
- Offer options
    - There are lots of hard-coded things that can't be changed in v0.1.0
- A real README
    - What imd is
    - How to use it
    - Plans for the future
    - How to interpret results
- HTTPS scanning
    - Basically the same stuff as HTTP
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
- Rust best practices
    - I'm sure there's plenty
