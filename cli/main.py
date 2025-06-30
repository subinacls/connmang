#!/usr/bin/env python3

import argparse
import json
import os
from connection_manager.core.ssh_manager import SSHManager

CONFIG_FILE = os.path.expanduser("~/.ssh_connections.json")
ssh_mgr = SSHManager()

def load_profiles():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_profiles(profiles):
    with open(CONFIG_FILE, 'w') as f:
        json.dump(profiles, f, indent=2)

def add_profile(args):
    profiles = load_profiles()
    if args.alias in profiles:
        print(f"[-] Alias '{args.alias}' already exists.")
        return

    profiles[args.alias] = {
        "host": args.host,
        "port": args.port,
        "username": args.username,
        "password": args.password,
        "key_file": args.key
    }
    save_profiles(profiles)
    print(f"[+] Profile '{args.alias}' saved.")

def connect(args):
    profiles = load_profiles()
    profile = profiles.get(args.alias)
    if not profile:
        print("[-] No such alias.")
        return

    try:
        ssh_mgr.connect(
            alias=args.alias,
            host=profile['host'],
            port=profile.get('port', 22),
            username=profile['username'],
            password=profile.get('password'),
            key_file=profile.get('key_file')
        )
    except Exception as e:
        print(f"[-] Connection error: {e}")

def shell(args):
    try:
        ssh_mgr.open_shell(args.alias, elevate=args.elevate)
    except Exception as e:
        print(f"[-] Shell error: {e}")

def sftp(args):
    try:
        ssh_mgr.open_sftp(args.alias)
    except Exception as e:
        print(f"[-] SFTP error: {e}")

def bg(args):
    try:
        ssh_mgr.background_shell(args.alias, elevate=args.elevate)
    except Exception as e:
        print(f"Error: {e}")  # or `pass` if intentionally left blank