#!/usr/bin/env python3
from pathlib import Path
import sys

FILE_PATH = Path(__file__).parent / "allowed_users.txt"

def load_users():
    if not FILE_PATH.exists():
        return set()
    with open(FILE_PATH, "r") as f:
        return {line.strip().lower() for line in f if line.strip()}

def save_users(users):
    with open(FILE_PATH, "w") as f:
        for user in sorted(users):
            f.write(user + "\n")

def add_user(email):
    users = load_users()
    email = email.strip().lower()
    if email in users:
        print(f"✅ {email} is already in the list.")
    else:
        users.add(email)
        save_users(users)
        print(f"✅ Added {email} to allowed users.")

def remove_user(email):
    users = load_users()
    email = email.strip().lower()
    if email not in users:
        print(f"⚠️ {email} was not in the list.")
    else:
        users.remove(email)
        save_users(users)
        print(f"🗑️ Removed {email} from allowed users.")

def list_users():
    users = load_users()
    if not users:
        print("No allowed users found.")
    else:
        print("📋 Allowed users:")
        for user in sorted(users):
            print(" -", user)

def main():
    if len(sys.argv) < 2:
        print("Usage: add_user.py [add|remove|list] [email]")
        sys.exit(1)

    action = sys.argv[1].lower()
    if action == "add" and len(sys.argv) == 3:
        add_user(sys.argv[2])
    elif action == "remove" and len(sys.argv) == 3:
        remove_user(sys.argv[2])
    elif action == "list":
        list_users()
    else:
        print("Usage: add_user.py [add|remove|list] [email]")

if __name__ == "__main__":
    main()
