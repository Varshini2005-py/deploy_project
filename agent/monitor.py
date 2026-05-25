"""
XAI-ITD-DLP — Background Monitoring Agent v2
Blocks: Ctrl+C, Ctrl+X, Ctrl+V, PrintScreen, Screenshots, USB
Monitors: File access, Active window, Heartbeat, Camera processes
New: USB alert popup, Camera/phone photo detection, stronger enforcement
"""

import time
import threading
import os
import sys
import subprocess
import requests
import psutil
import ctypes
from datetime import datetime

# ── Windows imports ───────────────────────────────────────────────────────────
try:
    import win32gui
    import win32con
    import win32clipboard
    WINDOWS = True
except ImportError:
    WINDOWS = False
    print("[AGENT] WARNING: pywin32 not installed. Run: pip install pywin32")

try:
    from pynput import keyboard
    PYNPUT = True
except ImportError:
    PYNPUT = False

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    WATCHDOG = True
except ImportError:
    WATCHDOG = False

# ── Config ────────────────────────────────────────────────────────────────────
SERVER_URL = os.environ.get("XAI_SERVER_URL", "https://xai-itd-dlp.onrender.com").rstrip("/")
HEARTBEAT_INTERVAL      = 5
CLIPBOARD_CLEAR_INTERVAL = 2
SENSITIVE_EXTENSIONS = {".pdf", ".docx", ".xlsx", ".csv", ".txt", ".pptx",
                        ".py", ".db", ".json", ".xml"}
MONITORED_PATHS = [
    os.path.expanduser("~/Documents"),
    os.path.expanduser("~/Desktop"),
    os.path.expanduser("~/Downloads"),
]

# Camera/phone-photography related processes to block
CAMERA_PROCESSES = [
    "WindowsCamera.exe",    # Windows Camera app
    "camera.exe",
    "Camera.exe",
    "iriun.exe",            # Iriun Webcam (phone as webcam)
    "DroidCam.exe",         # DroidCam (phone as webcam)
    "EpocCam.exe",          # EpocCam
    "iVCam.exe",            # iVCam
    "NDIWebcam.exe",
    "ManyCam.exe",
    "XSplit.exe",
    "OBS.exe",              # OBS Studio (screen/camera recording)
    "obs64.exe",
    "Bandicam.exe",
    "Fraps.exe",
    "ShareX.exe",           # ShareX screen capture
    "Greenshot.exe",
    "LightShot.exe",
]

SESSION_TOKEN = None
USER_EMAIL    = None
USER_NAME     = None
RUNNING       = True


def set_session(email, token, name="Employee"):
    global SESSION_TOKEN, USER_EMAIL, USER_NAME
    USER_EMAIL    = email
    SESSION_TOKEN = token
    USER_NAME     = name


def report(event_type, detail, risk="LOW", blocked=False):
    if not SESSION_TOKEN:
        return
    try:
        requests.post(
            f"{SERVER_URL}/api/agent/event",
            json={
                "email":      USER_EMAIL,
                "event_type": event_type,
                "detail":     detail,
                "risk_level": risk,
                "blocked":    blocked,
                "token":      SESSION_TOKEN
            },
            timeout=3
        )
    except Exception:
        pass


# ── POPUP ALERT (visible on screen) ──────────────────────────────────────────
def show_alert_popup(title, message):
    """Show a Windows message box on screen so employee sees the block reason."""
    if WINDOWS:
        try:
            # MB_ICONERROR | MB_SYSTEMMODAL (always on top, must click OK)
            ctypes.windll.user32.MessageBoxW(
                0,
                message,
                title,
                0x00000010 | 0x00001000  # MB_ICONERROR | MB_SYSTEMMODAL
            )
        except Exception:
            pass
    else:
        print(f"[ALERT] {title}: {message}")


def show_alert_nonblocking(title, message):
    """Show alert popup in background thread so agent doesn't pause."""
    threading.Thread(
        target=show_alert_popup,
        args=(title, message),
        daemon=True
    ).start()


# ── CLIPBOARD ─────────────────────────────────────────────────────────────────
def clear_clipboard():
    if not WINDOWS:
        return
    try:
        win32clipboard.OpenClipboard()
        win32clipboard.EmptyClipboard()
        win32clipboard.CloseClipboard()
    except Exception:
        try:
            win32clipboard.CloseClipboard()
        except Exception:
            pass
    try:
        ctypes.windll.user32.OpenClipboard(0)
        ctypes.windll.user32.EmptyClipboard()
        ctypes.windll.user32.CloseClipboard()
    except Exception:
        pass


def clipboard_watcher_loop():
    while RUNNING:
        time.sleep(CLIPBOARD_CLEAR_INTERVAL)
        if not WINDOWS:
            continue
        try:
            win32clipboard.OpenClipboard()
            has_bitmap = win32clipboard.IsClipboardFormatAvailable(win32con.CF_DIB)
            has_text   = (
                win32clipboard.IsClipboardFormatAvailable(win32con.CF_TEXT) or
                win32clipboard.IsClipboardFormatAvailable(win32con.CF_UNICODETEXT)
            )
            win32clipboard.EmptyClipboard()
            win32clipboard.CloseClipboard()

            if has_bitmap:
                report("SCREENSHOT_BLOCKED",
                       "Screenshot bitmap in clipboard — cleared.",
                       risk="HIGH", blocked=True)
                print("[AGENT] ⊘ SCREENSHOT BLOCKED — clipboard cleared")

            elif has_text:
                report("CLIPBOARD_BLOCKED",
                       "Clipboard text detected and cleared.",
                       risk="HIGH", blocked=True)
                print("[AGENT] ⊘ CLIPBOARD BLOCKED — cleared")

        except Exception:
            try:
                win32clipboard.CloseClipboard()
            except Exception:
                pass


# ── KEYBOARD BLOCKER ──────────────────────────────────────────────────────────
pressed_keys = set()

BLOCK_KEYS = {keyboard.Key.print_screen} if PYNPUT else set()

BLOCK_COMBOS = [
    {keyboard.Key.ctrl_l, keyboard.KeyCode.from_char('c')},
    {keyboard.Key.ctrl_r, keyboard.KeyCode.from_char('c')},
    {keyboard.Key.ctrl_l, keyboard.KeyCode.from_char('x')},
    {keyboard.Key.ctrl_r, keyboard.KeyCode.from_char('x')},
    {keyboard.Key.ctrl_l, keyboard.KeyCode.from_char('v')},
    {keyboard.Key.ctrl_r, keyboard.KeyCode.from_char('v')},
] if PYNPUT else []


def get_normalized(key):
    try:
        if hasattr(key, 'char') and key.char:
            return keyboard.KeyCode.from_char(key.char.lower())
    except Exception:
        pass
    return key


def on_press(key):
    norm = get_normalized(key)
    pressed_keys.add(norm)

    if key == keyboard.Key.print_screen:
        clear_clipboard()
        report("SCREENSHOT_BLOCKED", "PrintScreen BLOCKED.", risk="HIGH", blocked=True)
        print("[AGENT] ⊘ PrintScreen BLOCKED")
        show_alert_nonblocking(
            "XAI-ITD-DLP Security",
            "⊘ SCREENSHOT BLOCKED\n\nTaking screenshots is prohibited under company security policy.\nThis attempt has been logged and reported."
        )
        return False

    current = set(pressed_keys)
    for combo in BLOCK_COMBOS:
        if combo.issubset(current):
            clear_clipboard()
            if keyboard.KeyCode.from_char('c') in combo:
                label, msg = "COPY_BLOCKED",  "Ctrl+C (Copy) BLOCKED."
            elif keyboard.KeyCode.from_char('x') in combo:
                label, msg = "CUT_BLOCKED",   "Ctrl+X (Cut) BLOCKED."
            else:
                label, msg = "PASTE_BLOCKED", "Ctrl+V (Paste) BLOCKED."
            report(label, msg, risk="HIGH", blocked=True)
            print(f"[AGENT] ⊘ {label}")
            return False


def on_release(key):
    pressed_keys.discard(get_normalized(key))


def start_keyboard_blocker():
    if not PYNPUT:
        return None
    listener = keyboard.Listener(
        on_press=on_press,
        on_release=on_release,
        suppress=False
    )
    listener.start()
    print("[AGENT] ✅ Keyboard blocker active — Ctrl+C/X/V, PrintScreen BLOCKED")
    return listener


# ── SNIPPING TOOL BLOCKER ─────────────────────────────────────────────────────
def win_snip_blocker_loop():
    SNIP_PROCS = ["SnippingTool.exe", "ScreenSketch.exe", "SnipAndSketch.exe"]
    while RUNNING:
        time.sleep(2)
        for proc in psutil.process_iter(['name', 'pid']):
            try:
                if proc.info['name'] in SNIP_PROCS:
                    proc.kill()
                    report("SCREENSHOT_BLOCKED",
                           f"Snipping Tool blocked: {proc.info['name']}",
                           risk="HIGH", blocked=True)
                    print(f"[AGENT] ⊘ {proc.info['name']} KILLED")
                    show_alert_nonblocking(
                        "XAI-ITD-DLP Security",
                        f"⊘ SCREEN CAPTURE BLOCKED\n\n{proc.info['name']} has been terminated.\nScreen capture tools are prohibited under company policy."
                    )
            except Exception:
                pass


# ── CAMERA APP BLOCKER ───────────────────────────────────────────────────────
# Kills any screen recording / phone-as-webcam app running on the PC

_camera_warned_procs = set()

def camera_blocker_loop():
    """
    Kill any external camera app or screen-recording process.

    This runs ALWAYS (not just when a file is open).
    Blocks: Windows Camera, OBS, DroidCam, ShareX, Bandicam, etc.

    NOTE: This does NOT interfere with the agent's own OpenCV webcam capture
    (phone_detection_loop) — OpenCV uses the raw DirectShow API, not a
    separate camera process, so cv2.VideoCapture is invisible to psutil.

    If a camera app is blocked WHILE a file is open → also write phone flag
    so the browser closes the file immediately.
    """
    global _camera_warned_procs
    print("[AGENT] ✅ Camera/Recording app blocker active")
    while RUNNING:
        time.sleep(2)
        for proc in psutil.process_iter(['name', 'pid', 'exe']):
            try:
                pname = proc.info['name'] or ""
                if pname in CAMERA_PROCESSES:
                    pid = proc.info['pid']
                    if pid not in _camera_warned_procs:
                        _camera_warned_procs.add(pid)
                        try:
                            proc.kill()
                        except Exception:
                            pass
                        report("CAMERA_APP_BLOCKED",
                               f"Camera/recording app blocked and killed: {pname}",
                               risk="HIGH", blocked=True)
                        print(f"[AGENT] ⊘ CAMERA APP BLOCKED: {pname}")

                        # If employee currently has a file open → also flag as
                        # phone/recording threat so browser closes the file
                        try:
                            r = requests.get(
                                f"{SERVER_URL}/api/agent/file-viewing-status",
                                params={"token": SESSION_TOKEN, "email": USER_EMAIL},
                                timeout=2
                            )
                            if r.status_code == 200 and r.json().get("active", False):
                                _write_phone_flag()
                                show_alert_nonblocking(
                                    "XAI-ITD-DLP Security — Recording App Blocked",
                                    f"⊘ CAMERA APP BLOCKED\n\n"
                                    f"{pname} was detected and terminated.\n\n"
                                    "Camera and recording apps are prohibited while\n"
                                    "company documents are open.\n\n"
                                    "All files have been closed automatically.\n"
                                    "This incident has been logged and reported to your manager."
                                )
                            else:
                                # File not open — just show standard block notice
                                show_alert_nonblocking(
                                    "XAI-ITD-DLP Security — Camera App Blocked",
                                    f"⊘ CAMERA APP BLOCKED\n\n"
                                    f"{pname} has been terminated.\n\n"
                                    "Camera and recording software are not permitted\n"
                                    "on company workstations under the DLP policy.\n\n"
                                    "This incident has been logged and reported to your manager."
                                )
                        except Exception:
                            # Can't reach server — show generic popup
                            show_alert_nonblocking(
                                "XAI-ITD-DLP Security — Camera App Blocked",
                                f"⊘ CAMERA APP BLOCKED\n\n"
                                f"{pname} has been terminated.\n\n"
                                "Camera and recording software are not permitted\n"
                                "on company workstations under the DLP policy.\n\n"
                                "This incident has been logged and reported to your manager."
                            )
            except Exception:
                pass
        _camera_warned_procs = {p for p in _camera_warned_procs
                                 if psutil.pid_exists(p)}


# ── PHONE DETECTION via OpenCV webcam ────────────────────────────────────────
# How it works:
#   1. Browser calls /api/agent/file-viewing (active=true) when employee opens file
#   2. Agent polls that endpoint every second to check if file is open
#   3. When file is open → webcam turns ON → OpenCV scans for face/phone
#   4. If phone/person detected near screen → write flag file
#   5. Browser polls /api/agent/phone-status every 2s → sees flag → closes file

import cv2

# Face detector
_face_cascade = cv2.CascadeClassifier(
    cv2.data.haarcascades + 'haarcascade_frontalface_default.xml'
)
# Upper body detector — detects person holding phone toward screen
_upper_body_cascade = cv2.CascadeClassifier(
    cv2.data.haarcascades + 'haarcascade_upperbody.xml'
)

_phone_cooldown = 0   # prevent alert spam


# Track face history for disappearance detection
_face_history = []
_HISTORY_SIZE = 8   # check last 4 seconds (8 x 0.5s)

def detect_phone_in_frame(frame):
    """
    Smart face-based phone detection.
    
    Logic:
    - Employee normally sits with face visible (Faces=1)
    - When they hold phone to record, they often look at their phone
      screen = face turns away = Faces drops to 0
    - If face was consistently detected before and suddenly disappears
      = suspicious = ALERT
    - If 2+ faces appear = someone else brought phone near screen = ALERT
    - Faces=1 steady = normal working = SAFE
    """
    global _face_history

    gray  = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
    faces = _face_cascade.detectMultiScale(
        gray, scaleFactor=1.1, minNeighbors=3, minSize=(40, 40)
    )
    f = len(faces)

    # Keep history of last N frames
    _face_history.append(f)
    if len(_face_history) > _HISTORY_SIZE:
        _face_history.pop(0)

    # Not enough history yet — wait
    if len(_face_history) < _HISTORY_SIZE:
        return False, ""

    recent   = _face_history[-_HISTORY_SIZE:]
    avg_prev = sum(recent[:-2]) / max(len(recent[:-2]), 1)

    # Rule 1 — 2 or more faces = someone holding phone near screen
    if f >= 2:
        return True, f"Multiple persons detected near screen ({f} faces)"

    # Rule 2 — Face was consistently present before, now suddenly gone
    # Require: face was stable for at least 4 of last 6 frames (avg >= 0.65)
    # AND face has been gone for the last 2 consecutive frames (not just 1)
    # This prevents false positives from: leaning forward, poor lighting, brief occlusion
    last_two_gone = (len(recent) >= 2 and recent[-1] == 0 and recent[-2] == 0)
    if avg_prev >= 0.65 and last_two_gone:
        return True, "Employee face disappeared — possible phone recording attempt"

    return False, ""

def _is_file_open():
    """Ask Flask server if employee currently has a file open."""
    try:
        r = requests.get(
            f"{SERVER_URL}/api/agent/file-viewing-status",
            params={"token": SESSION_TOKEN, "email": USER_EMAIL},
            timeout=2
        )
        if r.status_code == 200:
            data = r.json()
            print(f"[AGENT] File status: {data}")
            return data.get("active", False)
    except Exception:
        pass
    return False


def _write_phone_flag():
    """Notify server via API that phone was detected — works on both local and Render."""
    try:
        requests.post(
            f"{SERVER_URL}/api/agent/phone-flag",
            headers={"X-Auth-Token": SESSION_TOKEN},
            timeout=3
        )
        print("[AGENT] Phone flag sent to server via API")
    except Exception as e:
        print(f"[AGENT] Phone flag API error: {e}")
        # Fallback: write local file (local dev only)
        try:
            safe_email = (USER_EMAIL or "unknown").replace("@", "_").replace(".", "_")
            flag_path  = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                f"phone_detected_{safe_email}.flag"
            )
            with open(flag_path, "w") as _f:
                _f.write(datetime.utcnow().isoformat())
            print(f"[AGENT] Flag written locally (fallback): {flag_path}")
        except Exception as e2:
            print(f"[AGENT] Flag write error: {e2}")


_push_counter = 0

def _push_frame(frame):
    """Encode frame as JPEG and push to Flask for browser camera overlay."""
    global _push_counter
    _push_counter += 1
    if _push_counter % 3 != 0:   # every 3rd frame = ~5fps
        return
    if not SESSION_TOKEN:
        return
    try:
        ok, buf = cv2.imencode('.jpg', frame, [cv2.IMWRITE_JPEG_QUALITY, 55])
        if not ok:
            return
        requests.post(
            f"{SERVER_URL}/api/agent/push-frame",
            data=buf.tobytes(),
            headers={"X-Auth-Token": SESSION_TOKEN, "Content-Type": "image/jpeg"},
            timeout=1
        )
        print("[AGENT] 📸 Frame pushed to browser")
    except Exception as e:
        print(f"[AGENT] Push frame error: {e}")


def phone_detection_loop():
    """
    Main phone detection loop.
    - Webcam is OFF when no file is open (saves CPU + battery)
    - Webcam turns ON automatically when employee opens a file
    - OpenCV checks every 0.5s for face/phone near screen
    - If detected: flag file written, browser closes the file
    """
    global _phone_cooldown

    print("[AGENT] ✅ Phone detection active — webcam starts when file is opened")

    cap           = None
    cam_open      = False
    was_file_open = False

    while RUNNING:
        time.sleep(0.5)

        file_open = _is_file_open()

        # File just opened — turn webcam ON
        if file_open and not cam_open:
            try:
                # Try index 0 first, then 1 (some systems have virtual cam at 0)
                cap = None
                for cam_idx in [0, 1, 2]:
                    _cap = cv2.VideoCapture(cam_idx, cv2.CAP_DSHOW)
                    if _cap.isOpened():
                        cap = _cap
                        print(f"[AGENT] 📷 Webcam ON (index {cam_idx}) — monitoring for phone/recording")
                        break
                    else:
                        _cap.release()

                if cap and cap.isOpened():
                    cam_open = True
                    report("WEBCAM_STARTED",
                           "Webcam monitoring started — employee opened a file.",
                           risk="LOW")
                else:
                    print("[AGENT] ⚠ Could not open any webcam — phone detection unavailable")
                    print("[AGENT]   Make sure a webcam is connected and not in use by another app")
                    cap = None
                    # Still set cam_open=True so we don't retry every 0.5s
                    cam_open = True   # will skip frame capture below since cap is None
            except Exception as e:
                print(f"[AGENT] Webcam open error: {e}")

        # File just closed — turn webcam OFF
        if not file_open and cam_open:
            try:
                if cap:
                    cap.release()
                    cap = None
                cam_open = False
                print("[AGENT] 📷 Webcam OFF — file closed")
                report("WEBCAM_STOPPED",
                       "Webcam monitoring stopped — file closed.",
                       risk="LOW")
            except Exception:
                pass

        # Webcam is ON — scan for phone
        if cam_open and cap:
            try:
                ret, frame = cap.read()
                if not ret or frame is None:
                    continue

                # Push frame to Flask so browser camera overlay can display it
                _push_frame(frame)

                phone_detected, reason = detect_phone_in_frame(frame)

                if phone_detected:
                    now = time.time()
                    if now - _phone_cooldown > 10:   # 10s cooldown between alerts
                        _phone_cooldown = now
                        print(f"[AGENT] ⊘ PHONE DETECTED: {reason}")
                        report("PHONE_DETECTED",
                               f"Phone recording attempt: {reason}. File auto-closed.",
                               risk="HIGH", blocked=True)
                        _write_phone_flag()
                        show_alert_nonblocking(
                            "XAI-ITD-DLP Security — Recording Detected",
                            f"⊘ PHONE RECORDING DETECTED\n\n{reason}\n\n"
                            "Someone is attempting to photograph or record\n"
                            "the screen using an external device.\n\n"
                            "The file has been closed automatically.\n"
                            "This incident has been logged and reported to your manager."
                        )

            except Exception as e:
                print(f"[AGENT] Detection error: {e}")

        was_file_open = file_open

    # Cleanup on exit
    if cap:
        cap.release()


# ── USB MONITOR ───────────────────────────────────────────────────────────────
known_drives = set()


def get_removable_drives():
    drives = set()
    for p in psutil.disk_partitions(all=False):
        if 'removable' in p.opts.lower():
            drives.add(p.device)
    return drives


def eject_drive(drive):
    if not WINDOWS:
        return
    try:
        letter = drive.replace("\\", "").replace("/", "").rstrip(":")
        subprocess.run(["mountvol", letter + ":\\", "/p"],
                       capture_output=True, timeout=5)
    except Exception:
        pass


def usb_monitor_loop():
    global known_drives
    known_drives = get_removable_drives()
    print("[AGENT] ✅ USB monitor active — USB ports BLOCKED")
    while RUNNING:
        time.sleep(3)
        try:
            current = get_removable_drives()
            for drive in current - known_drives:
                # Show popup FIRST so employee sees it immediately
                show_alert_nonblocking(
                    "XAI-ITD-DLP Security — USB BLOCKED",
                    f"⊘ USB PORT IS BLOCKED\n\nDrive: {drive}\n\n"
                    "USB storage devices are prohibited under company security policy.\n"
                    "The device is being ejected automatically.\n\n"
                    "This incident has been logged and reported to your manager."
                )
                report("USB_INSERTED",
                       f"USB inserted: {drive} — auto-ejected per policy.",
                       risk="HIGH", blocked=True)
                print(f"[AGENT] ⊘ USB BLOCKED + EJECTING: {drive}")
                eject_drive(drive)

            for drive in known_drives - current:
                report("USB_REMOVED", f"USB removed: {drive}", risk="LOW")
                print(f"[AGENT] USB removed: {drive}")

            known_drives = current
        except Exception:
            pass


# ── FILE MONITOR ──────────────────────────────────────────────────────────────
if WATCHDOG:
    class SensitiveFileHandler(FileSystemEventHandler):
        def _is_sensitive(self, path):
            return os.path.splitext(path)[1].lower() in SENSITIVE_EXTENSIONS

        def on_modified(self, event):
            if not event.is_directory and self._is_sensitive(event.src_path):
                report("FILE_MODIFIED", f"Modified: {os.path.basename(event.src_path)}", risk="MEDIUM")
                print(f"[AGENT] FILE_MODIFIED: {os.path.basename(event.src_path)}")
                try:
                    from dlp.policy_engine import scan_and_enforce
                    scan_and_enforce(
                        file_path         = event.src_path,
                        user_email        = USER_EMAIL,
                        action_type       = "FILE_MODIFIED",
                        destination       = "-",
                        socketio_instance = None
                    )
                except Exception as _dlp_err:
                    print(f"[AGENT] DLP scan error (on_modified): {_dlp_err}")

        def on_moved(self, event):
            report("FILE_MOVED",
                   f"Moved: {os.path.basename(event.src_path)} → {os.path.basename(event.dest_path)}",
                   risk="HIGH")
            print(f"[AGENT] FILE_MOVED: {os.path.basename(event.src_path)}")

        def on_deleted(self, event):
            if not event.is_directory and self._is_sensitive(event.src_path):
                report("FILE_DELETED", f"Deleted: {os.path.basename(event.src_path)}", risk="HIGH")
                print(f"[AGENT] FILE_DELETED: {os.path.basename(event.src_path)}")

        def on_created(self, event):
            if not event.is_directory and self._is_sensitive(event.src_path):
                report("FILE_CREATED", f"Created: {os.path.basename(event.src_path)}", risk="MEDIUM")
                print(f"[AGENT] FILE_CREATED: {os.path.basename(event.src_path)}")
                try:
                    from dlp.policy_engine import scan_and_enforce
                    scan_and_enforce(
                        file_path         = event.src_path,
                        user_email        = USER_EMAIL,
                        action_type       = "FILE_CREATED",
                        destination       = "-",
                        socketio_instance = None
                    )
                except Exception as _dlp_err:
                    print(f"[AGENT] DLP scan error (on_created): {_dlp_err}")


def start_file_monitor():
    if not WATCHDOG:
        return None
    observer = Observer()
    handler  = SensitiveFileHandler()
    for path in MONITORED_PATHS:
        if os.path.exists(path):
            observer.schedule(handler, path, recursive=True)
    observer.start()
    print("[AGENT] ✅ File monitor active on Documents, Desktop, Downloads")
    return observer


# ── ACTIVE WINDOW ─────────────────────────────────────────────────────────────
last_window = ""

def active_window_loop():
    global last_window
    print("[AGENT] ✅ Active window monitor active")
    while RUNNING:
        time.sleep(5)
        if not WINDOWS:
            continue
        try:
            hwnd  = win32gui.GetForegroundWindow()
            title = win32gui.GetWindowText(hwnd)
            if title and title != last_window:
                last_window = title
                report("ACTIVE_WINDOW", f"Window: {title}", risk="LOW")
                print(f"[AGENT] Window: {title}")
        except Exception:
            pass


# ── HEARTBEAT ─────────────────────────────────────────────────────────────────
def heartbeat_loop():
    print("[AGENT] ✅ Heartbeat active")
    while RUNNING:
        report("HEARTBEAT", f"Agent active — {USER_NAME}", risk="LOW")
        print("[AGENT] ♥ Heartbeat")
        time.sleep(HEARTBEAT_INTERVAL)


# ── MAIN ──────────────────────────────────────────────────────────────────────
def start_agent(email, token, name="Employee"):
    global RUNNING
    RUNNING = True
    set_session(email, token, name)

    print("=" * 60)
    print(f"  XAI-ITD-DLP Monitoring Agent — {name}")
    print("=" * 60)
    print("  BLOCKED  : Ctrl+C, Ctrl+X, Ctrl+V, PrintScreen")
    print("  BLOCKED  : Screenshots, Snipping Tool, USB ports")
    print("  BLOCKED  : Camera apps, Phone-as-webcam apps")
    print("  BLOCKED  : OBS, ShareX, Bandicam, ManyCam, etc.")
    print("  DETECTED : Phone near screen (OpenCV — active when file open)")
    print("  MONITORED: Files, Windows, Clipboard, Heartbeat")
    print("=" * 60 + "\n")

    report("AGENT_STARTED", f"Monitoring agent v3 started for {name}.", risk="LOW")

    threads = [
        threading.Thread(target=usb_monitor_loop,       daemon=True),
        threading.Thread(target=clipboard_watcher_loop,  daemon=True),
        threading.Thread(target=active_window_loop,      daemon=True),
        threading.Thread(target=heartbeat_loop,          daemon=True),
        threading.Thread(target=win_snip_blocker_loop,   daemon=True),
        threading.Thread(target=camera_blocker_loop,     daemon=True),
        threading.Thread(target=phone_detection_loop,    daemon=True),  # NEW
    ]
    for t in threads:
        t.start()

    kb_listener = start_keyboard_blocker()
    observer    = start_file_monitor()

    # Keep running until RUNNING is set to False externally (by launcher on new login)
    try:
        while RUNNING:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        RUNNING = False
        if observer:
            try: observer.stop(); observer.join(timeout=3)
            except Exception: pass
        if kb_listener:
            try: kb_listener.stop()
            except Exception: pass
        report("AGENT_STOPPED", "Agent stopped.", risk="LOW")
        print("\n[AGENT] Stopped.")


# ── STANDALONE ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import json
    TOKEN_FILE = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "session_token.json"
    )
    if os.path.exists(TOKEN_FILE):
        with open(TOKEN_FILE) as f:
            s = json.load(f)
        email = s["email"]
        token = s["token"]
        name  = s.get("name", "Employee")
        print(f"Auto-loaded: {name} ({email})")
    else:
        email = input("Employee email: ").strip()
        token = input("Session token:  ").strip()
        name  = input("Your name:      ").strip() or "Employee"

    start_agent(email, token, name)