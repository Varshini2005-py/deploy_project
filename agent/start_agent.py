"""
XAI-ITD-DLP — Agent Auto-Launcher
Connects to server via API login — works with both localhost and Render.

First login  → OTP required once → token saved to saved_sessions/<email>.json
Next time    → token loaded automatically, NO OTP needed
Multiple employees → each has their own saved session file

Usage:
  python start_agent.py                        # prompts to pick/add employee
  python start_agent.py --email ravi@co.com    # launch directly for that email
"""

import os
import sys
import json
import time
import threading
import requests
import getpass
import argparse

# agent/ folder → parent is project root
AGENT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR  = os.path.dirname(AGENT_DIR)

# Saved sessions folder — one JSON per employee
SESSIONS_DIR = os.path.join(AGENT_DIR, "saved_sessions")
os.makedirs(SESSIONS_DIR, exist_ok=True)

# Legacy single token file (still written for backwards compat)
TOKEN_FILE = os.path.join(ROOT_DIR, "session_token.json")

sys.path.insert(0, ROOT_DIR)
sys.path.insert(0, AGENT_DIR)

# ── Server URL ────────────────────────────────────────────────────────────────
SERVER_URL = os.environ.get(
    "XAI_SERVER_URL",
    "https://xai-itd-dlp.onrender.com"
).rstrip("/")


# ── Session file helpers ──────────────────────────────────────────────────────

def _session_path(email):
    """Return path to saved session file for this email."""
    safe = email.replace("@", "_at_").replace(".", "_").replace("/", "_")
    return os.path.join(SESSIONS_DIR, f"{safe}.json")


def load_saved_session(email):
    """Load saved token for email. Returns (email, token, name) or None."""
    path = _session_path(email)
    try:
        with open(path, "r") as f:
            s = json.load(f)
        token = s.get("token", "").strip()
        name  = s.get("name", "Employee").strip()
        if token:
            return email, token, name
    except Exception:
        pass
    return None


def save_session(email, token, name):
    """Save token to per-employee file so next launch skips OTP."""
    path = _session_path(email)
    try:
        with open(path, "w") as f:
            json.dump({"email": email, "token": token, "name": name}, f, indent=2)
        # Also write legacy single token file
        with open(TOKEN_FILE, "w") as f:
            json.dump({"email": email, "token": token, "name": name}, f, indent=2)
        print(f"[LAUNCHER] Session saved → {path}")
    except Exception as e:
        print(f"[LAUNCHER] Could not save session: {e}")


def delete_saved_session(email):
    """Remove saved session so employee must re-authenticate next time."""
    path = _session_path(email)
    try:
        if os.path.exists(path):
            os.remove(path)
            print(f"[LAUNCHER] Saved session removed for {email}")
    except Exception:
        pass


def list_saved_sessions():
    """Return list of (email, name) for all saved sessions."""
    sessions = []
    for fname in os.listdir(SESSIONS_DIR):
        if not fname.endswith(".json"):
            continue
        fpath = os.path.join(SESSIONS_DIR, fname)
        try:
            with open(fpath, "r") as f:
                s = json.load(f)
            email = s.get("email", "").strip()
            name  = s.get("name", "Employee").strip()
            if email:
                sessions.append((email, name))
        except Exception:
            pass
    return sessions


def validate_token(email, token):
    """Ping server to check if saved token is still valid."""
    try:
        res = requests.get(
            f"{SERVER_URL}/api/agent/file-viewing-status",
            params={"token": token, "email": email},
            timeout=5
        )
        # 200 or 403 both mean server is reachable;
        # 403 = token expired, 200 = still valid
        return res.status_code == 200
    except Exception:
        # Server unreachable — assume token still valid (offline mode)
        print("[LAUNCHER] Could not reach server to validate token — using saved session anyway.")
        return True


# ── Login via OTP ─────────────────────────────────────────────────────────────

def login_via_api(email, password):
    """OTP login flow. Returns (token, name) or None."""
    try:
        res = requests.post(
            f"{SERVER_URL}/api/auth/request-otp",
            json={"email": email, "password": password},
            timeout=15
        )
        if res.status_code == 200:
            print(f"[LAUNCHER] {res.json().get('message', 'OTP sent to your email.')}")
            otp = input("Enter OTP from your email: ").strip()
            res2 = requests.post(
                f"{SERVER_URL}/api/auth/verify-otp",
                json={"email": email, "otp": otp},
                timeout=15
            )
            if res2.status_code == 200:
                data  = res2.json()
                token = data.get("token", "")
                name  = data.get("name", "Employee")
                if token:
                    return token, name
            print(f"[LAUNCHER] OTP verification failed: {res2.text[:120]}")
        else:
            print(f"[LAUNCHER] Login failed ({res.status_code}): {res.json().get('error', res.text[:120])}")
    except requests.exceptions.ConnectionError:
        print(f"[LAUNCHER] Cannot reach server at {SERVER_URL}")
        print("[LAUNCHER] Check your internet connection or XAI_SERVER_URL env var.")
    except Exception as e:
        print(f"[LAUNCHER] Login error: {e}")
    return None


# ── Employee picker ───────────────────────────────────────────────────────────

def pick_or_add_employee():
    """
    Show saved employees. User can:
      - Pick an existing one (no OTP)
      - Add a new one (OTP once, then saved)
    Returns (email, token, name).
    """
    saved = list_saved_sessions()

    if saved:
        print("\n[LAUNCHER] Saved employees:")
        for i, (em, nm) in enumerate(saved, 1):
            print(f"  {i}. {nm} ({em})")
        print(f"  {len(saved)+1}. Add new employee")
        print(f"  {len(saved)+2}. Remove a saved session")

        while True:
            choice = input(f"\nSelect [1-{len(saved)+2}]: ").strip()
            try:
                idx = int(choice)
            except ValueError:
                print("Please enter a number.")
                continue

            # Pick existing employee
            if 1 <= idx <= len(saved):
                email, name = saved[idx - 1]
                print(f"[LAUNCHER] Loading saved session for {name} ({email})...")
                saved_data = load_saved_session(email)
                if saved_data:
                    _, token, name = saved_data
                    # Validate token is still accepted by server
                    if validate_token(email, token):
                        print(f"[LAUNCHER] ✅ Session valid — no OTP needed!")
                        return email, token, name
                    else:
                        print(f"[LAUNCHER] ⚠ Saved token expired. Re-login required.")
                        delete_saved_session(email)
                        # Fall through to fresh login below
                        return _fresh_login(email)
                else:
                    print("[LAUNCHER] Could not read saved session. Re-login required.")
                    return _fresh_login(email)

            # Add new employee
            elif idx == len(saved) + 1:
                return _fresh_login()

            # Remove saved session
            elif idx == len(saved) + 2:
                rem_choice = input(f"Remove which? [1-{len(saved)}]: ").strip()
                try:
                    rem_idx = int(rem_choice) - 1
                    if 0 <= rem_idx < len(saved):
                        delete_saved_session(saved[rem_idx][0])
                        return pick_or_add_employee()  # re-show menu
                except ValueError:
                    pass
                print("Invalid choice.")
            else:
                print("Invalid choice.")
    else:
        # No saved sessions at all — go straight to login
        print("[LAUNCHER] No saved sessions found.")
        return _fresh_login()


def _fresh_login(email=None):
    """Login with OTP and save session. Returns (email, token, name)."""
    while True:
        if not email:
            email = input("Employee email:  ").strip()
        password = getpass.getpass("Password:        ")
        result   = login_via_api(email, password)
        if result:
            token, name = result
            save_session(email, token, name)
            print(f"[LAUNCHER] ✅ Welcome {name}! Session saved — no OTP next time.")
            return email, token, name
        else:
            print("[LAUNCHER] Try again.\n")
            email = None  # reset so user can re-enter email too


# ── Agent runner ──────────────────────────────────────────────────────────────

def run_agent(monitor, email, token, name):
    """Start agent thread and watch for crashes."""
    monitor.RUNNING = True
    agent_thread = threading.Thread(
        target=monitor.start_agent,
        args=(email, token, name),
        daemon=True
    )
    agent_thread.start()
    return agent_thread


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="XAI-ITD-DLP Agent Launcher")
    parser.add_argument("--email", help="Employee email to launch directly (skips menu)")
    args = parser.parse_args()

    print("=" * 55)
    print("  XAI-ITD-DLP Agent Launcher")
    print(f"  Server : {SERVER_URL}")
    print(f"  Sessions: {SESSIONS_DIR}")
    print("=" * 55)

    import monitor
    monitor.SERVER_URL = SERVER_URL

    while True:
        # ── Direct launch by email (--email flag or restart after switch) ──
        if args.email:
            saved = load_saved_session(args.email)
            if saved:
                email, token, name = saved
                if validate_token(email, token):
                    print(f"[LAUNCHER] ✅ Auto-loaded session for {name} ({email})")
                else:
                    print(f"[LAUNCHER] Token expired for {args.email} — re-login required.")
                    delete_saved_session(args.email)
                    email, token, name = _fresh_login(args.email)
            else:
                print(f"[LAUNCHER] No saved session for {args.email} — login required.")
                email, token, name = _fresh_login(args.email)
            args.email = None  # clear so next loop shows menu
        else:
            # ── Interactive picker ─────────────────────────────────────────
            email, token, name = pick_or_add_employee()

        print(f"\n[LAUNCHER] Starting monitoring agent for {name}...\n")
        agent_thread = run_agent(monitor, email, token, name)

        print("[LAUNCHER] Monitoring active. Press Ctrl+C to stop.")

        try:
            while True:
                time.sleep(2)

                # Agent thread crashed — restart automatically
                if not agent_thread.is_alive():
                    print("[LAUNCHER] Agent stopped unexpectedly — restarting in 3s...")
                    time.sleep(3)
                    agent_thread = run_agent(monitor, email, token, name)

        except KeyboardInterrupt:
            print(f"\n[LAUNCHER] Stopped monitoring {name}.")
            monitor.RUNNING = False
            time.sleep(1)

            print("\nOptions:")
            print("  1. Switch to another employee")
            print("  2. Re-login current employee (clears saved session)")
            print("  3. Exit")
            choice = input("Choose [1/2/3]: ").strip()

            if choice == "1":
                continue   # back to picker menu
            elif choice == "2":
                delete_saved_session(email)
                args.email = email
                continue   # re-login same email
            else:
                break


if __name__ == "__main__":
    main()