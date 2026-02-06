# Python Honeypot: Trap & Monitor Cyber Attacks
A multi-service honeypot built in Python that emulates SSH and Web vulnerability to trap bots and analyze attacker behavior.
## Overview
This project is a custom-built Honeypot designed to mimic a vulnerable server. It listens for incoming connections on specific ports (like SSH and HTTP), emulating a fake shell and a fake web server. When an attacker or bot attempts to brute-force credentials or exploit the system, their actions are logged, and they are contained within a harmless environment.

This tool is strictly for educational and defensive research purposes, allowing blue-teamers and students to understand how botnets scan the internet and what commands attackers run once they think they're inside.

## Key Features
* FAKE SSH Server: mimicks a real SSH service using the paramiko library.

* Emulated Shell: provides intruders with a fake terminal where they can run commands (like ls, cd, pwd) without actually touching the host system.

* Web Honeypot: hosts a fake web interface to catch HTTP scanners.

* Active Logging: captures IP addresses, usernames, passwords, and every command executed by the attacker.

* Multi-Threaded: handles multiple intruder connections simultaneously.

## Tech Stack
- **Python 3** - Core logic
- **Socket** - Networking & connection handling
- **Paramiko** - SSH server interface
- **Threading** - Concurrent connections


## How It Works
* The Trap: The script opens ports (e.g., 22 for SSH, 80 for Web) and waits.

* The Deception: When a bot connects, the script presents a realistic-looking login banner.

* The Capture: It accepts any password (or specific weak ones) to let the attacker "in."

* The Intelligence: Once inside the emulated shell, every keystroke and command the attacker types is saved to a log file for analysis.

## Installation & Usage
Clone the Repository

```
git clone https://github.com/lolo-ikh/Honeypot.git
cd python-honeypot
```
Install Dependencies

```
pip install paramiko
```
Generate RSA Key (For SSH) The SSH server requires a host key to run.

```
ssh-keygen -t rsa -f server.key
```
Run the Honeypot Note: You may need sudo to bind to low-level ports like 22 or 80.

```
sudo python3 honeypot.py
```
## ⚠️ Disclaimer
This project is for educational and research purposes only.

Do not run this on a production server unless you know exactly what you are doing.

Do not use this code to target or hack systems you do not own.

The author is not responsible for any damage caused by the misuse of this software.

## What I Learned
Building this project taught me:

How the SSH Protocol negotiates connections.

How to use Python Sockets to build custom servers.

The importance of Log Analysis in Cyber Security.

How Botnets automatically scan the entire internet for weak passwords.
