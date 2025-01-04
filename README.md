# My Honeypot

## Purpose
It is difficult to detect any attackers or bots accessing your IP address. As such, I was inspired to create a simple honeypot using Python. This logs the date, time, and address of each time the attacker attempts to log in to my address via port and server number.

## How to Use

1) Clone repository with ""
2) In your terminal (I used gitbash), type "ssh-keygen -t rsa -b 2048 -f host_key" to generate the required host key.
3) Run honeypot_MT.py

## Future Goals

* embed a honeypot on a simple webpage (fake website with exam answers - catch cheaters)
