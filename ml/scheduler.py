"""
Task 5 - AI Risk Engine Scheduler
File : D:/rajasri/xai_itd_dlp/ml/scheduler.py

Pipeline (runs every hour):
  1. analyze_behavior.py  -> behavior_profiles + user_baselines
  2. detect_anomaly.py    -> threat_scores
  3. enforce_dlp.py       -> ai_alerts
  4. explain_shap.py      -> shap_explanations   ← NEW (Module 3)
"""

import os
import sys
import time
import threading
import importlib.util
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

SCAN_INTERVAL_SECONDS = 3600
ML_DIR = os.path.dirname(os.path.abspath(__file__))

_scheduler_started = False


# =============================================================================
# MODULE LOADER
# =============================================================================

def _load(name, filename):
    path = os.path.join(ML_DIR, filename)
    spec = importlib.util.spec_from_file_location(name, path)
    mod  = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# =============================================================================
# SINGLE SCAN RUN
# =============================================================================

def run_once(socketio_instance=None):
    start = datetime.utcnow()
    print(f"\n[SCHEDULER] ========== AI Scan started at {start.strftime('%Y-%m-%d %H:%M:%S')} ==========")

    # ── Step 1: Behavior Analysis ─────────────────────────────────────────────
    try:
        print("[SCHEDULER] Step 1/4 — Updating behavior profiles...")
        analyze = _load("analyze_behavior", "analyze_behavior.py")
        analyze.build_all_employee_profiles(days_back=30)
        analyze.build_user_baseline()
        print("[SCHEDULER] Step 1/4 — Done")
    except Exception as e:
        print(f"[SCHEDULER ERROR] Step 1 failed: {e}")
        import traceback; traceback.print_exc()
        return False

    # ── Step 2: Anomaly Detection ─────────────────────────────────────────────
    # detect_anomaly.load_models() returns a dict:
    # { "iso", "lof", "lstm", "gcn", "node_order",
    #   "user_features", "scaler", "seq_scaler" }
    models = None
    try:
        print("[SCHEDULER] Step 2/4 — Scoring anomalies...")
        detect = _load("detect_anomaly", "detect_anomaly.py")
        models = detect.load_models()
        if models is None:
            print("[SCHEDULER] No saved models — training now (one-time, ~10-20 min)...")
            models = detect.train_all_models()
        if models is None:
            print("[SCHEDULER ERROR] Could not load or train models — skipping scan")
            return False
        detect.score_all_employees(models)
        print("[SCHEDULER] Step 2/4 — Done")
    except Exception as e:
        print(f"[SCHEDULER ERROR] Step 2 failed: {e}")
        import traceback; traceback.print_exc()
        return False

    # ── Step 3: Enforcement ───────────────────────────────────────────────────
    try:
        print("[SCHEDULER] Step 3/4 — Running enforcement...")
        enforce = _load("enforce_dlp", "enforce_dlp.py")
        enforce.run_enforcement(socketio_instance=socketio_instance)
        print("[SCHEDULER] Step 3/4 — Done")
    except Exception as e:
        print(f"[SCHEDULER ERROR] Step 3 failed: {e}")
        import traceback; traceback.print_exc()
        return False

    # ── Step 4: SHAP Explanations ─────────────────────────────────────────────
    # Pass iso + scaler from the already-loaded models dict
    # so explain_shap doesn't reload from disk
    try:
        print("[SCHEDULER] Step 4/4 — Computing SHAP explanations...")
        explain = _load("explain_shap", "explain_shap.py")
        explain.run_shap_explanations(
            iso_model = models["iso"],
            scaler    = models["scaler"]
        )
        print("[SCHEDULER] Step 4/4 — Done")
    except Exception as e:
        # SHAP failure is non-fatal — steps 1-3 already completed
        print(f"[SCHEDULER WARNING] Step 4 (SHAP) failed: {e}")
        import traceback; traceback.print_exc()

    elapsed = (datetime.utcnow() - start).seconds
    print(f"[SCHEDULER] ========== Scan complete in {elapsed}s ==========\n")
    return True


# =============================================================================
# SCHEDULER LOOP
# =============================================================================

def _scheduler_loop(socketio_instance=None):
    print(f"[SCHEDULER] Started — will scan every {SCAN_INTERVAL_SECONDS // 60} minute(s)")
    run_once(socketio_instance=socketio_instance)
    while True:
        time.sleep(SCAN_INTERVAL_SECONDS)
        run_once(socketio_instance=socketio_instance)


def start_scheduler(socketio_instance=None):
    global _scheduler_started
    if _scheduler_started:
        print("[SCHEDULER] Already running — skipping duplicate start")
        return
    _scheduler_started = True
    t = threading.Thread(
        target=_scheduler_loop,
        args=(socketio_instance,),
        daemon=True,
        name="AIScheduler"
    )
    t.start()
    print("[SCHEDULER] Background AI scan thread started")


# =============================================================================
# STANDALONE RUN
# =============================================================================

if __name__ == "__main__":
    print("=" * 60)
    print("  XAI-ITD-DLP — AI Risk Engine Scheduler")
    print(f"  Scan interval : every {SCAN_INTERVAL_SECONDS // 60} minute(s)")
    print("  Press Ctrl+C to stop")
    print("=" * 60)
    try:
        run_once()
        print(f"\n[SCHEDULER] Next scan in {SCAN_INTERVAL_SECONDS // 60} minute(s). Waiting...")
        while True:
            time.sleep(SCAN_INTERVAL_SECONDS)
            run_once()
    except KeyboardInterrupt:
        print("\n[SCHEDULER] Stopped by user.")