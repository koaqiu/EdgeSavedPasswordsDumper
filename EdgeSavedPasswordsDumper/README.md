## EdgeSavedPasswordsDumper
*A small educational tool demonstrating that Edge stores credentials in cleartext in process memory.*

---

## Overview
This project is a simple C# tool created to demonstrate that Edge stores credentials in cleartext in memory. It is intended for **educational and research purposes only**, especially for understanding memory inspection, credential handling, and security design differences across software.

I am **not an experienced C# developer**, so the code may contain rough edges, inefficiencies, or non‑idiomatic patterns. Contributions, improvements, and suggestions are welcome.

---

## Purpose
This tool was created to show that whenever a user stores credentials in Edge (using the Microsoft Password Manager feature, e.g. Autofill), ALL credentials are stored in plaintext in the parent Edge process memory. This is obviously problematic in a shared environment (e.g. on a terminal servers) as an attacker can access **all** Edge processes for **all** logged on and disconnected users, and dump their saved credentials.
Microsoft has said that this is "by design" and thus won't fix this.
The tool is meant to support learning, responsible disclosure, and security awareness — not misuse.

---

## Disclaimer
This software is provided **strictly for educational use**.

By using this project, you agree that:
- You are solely responsible for how you use this code  
- You will not use it to violate privacy, security policies, or any applicable laws  
- The author provides **no warranty** of any kind  
- The author **cannot be held liable** for any misuse, damage, or consequences resulting from this software  

You accept full responsibility for ensuring your actions comply with all legal and ethical requirements.

---

## Features
- Demonstrates that Edge stores save credentials in clear text in memory

---

## Requirements
- Any Edge versions that's Chromium based (from version 79 and newer, including 147.0.3912.98 and any **future** version, as Microsoft won't change this feature).
- .NET Framework **4.8.1** (changed from 3.5 originally)
- Can be run without Adminstrator rights, but will only be able to access Edge processes ran by the same user
- If run with Administrator privileges, the program can access and read memory from other users’ Edge processes on the same machine 
