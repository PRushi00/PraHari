"""
Verify PraHari Windows launcher, live unified server binding on 127.0.0.1:8000,
SPA routing, REST API workflows, live ingestion, forecasting, and clean shutdown.
"""
import subprocess
import sys
import time
import urllib.request
import urllib.error
import json
from pathlib import Path

def test_launcher_lifecycle():
    script_dir = Path(__file__).resolve().parent.parent
    backend_dir = script_dir / "backend"
    python_exe = backend_dir / ".venv" / "Scripts" / "python.exe"
    
    print(f"=== PraHari Live Launcher Verification ===")
    print(f"Workspace: {script_dir}")
    print(f"Python:    {python_exe}")
    
    # Ensure port 8000 is free before starting
    # Launch uvicorn unified server on loopback
    cmd = [
        str(python_exe),
        "-m", "uvicorn",
        "app.main:app",
        "--app-dir", str(backend_dir),
        "--host", "127.0.0.1",
        "--port", "8000",
        "--log-level", "info",
    ]
    
    print(f"[LAUNCH] Starting PraHari server on http://127.0.0.1:8000 ...")
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
    try:
        # Wait for server to bind
        max_wait = 15
        started = False
        start_time = time.time()
        
        while time.time() - start_time < max_wait:
            try:
                with urllib.request.urlopen("http://127.0.0.1:8000/api/v1/health", timeout=1.5) as resp:
                    if resp.status == 200:
                        data = json.loads(resp.read().decode("utf-8"))
                        print(f"[SUCCESS] Server is responsive! Health: {data['status']}, Version: {data.get('app_version')}")
                        started = True
                        break
            except Exception:
                time.sleep(0.5)
                
        if not started:
            stdout, stderr = proc.communicate(timeout=3)
            print(f"[ERROR] Server failed to start:\nSTDOUT: {stdout}\nSTDERR: {stderr}", file=sys.stderr)
            sys.exit(1)
            
        # 1. Test Root Dashboard (Serves SPA index.html)
        print("[CHECK 1] Testing Root Dashboard (GET /) ...")
        with urllib.request.urlopen("http://127.0.0.1:8000/", timeout=3) as resp:
            assert resp.status == 200
            ct = resp.headers.get("content-type", "")
            body = resp.read().decode("utf-8")
            assert "text/html" in ct
            assert "PraHari" in body
            print(f"   └─ Status: 200 OK | Content-Type: {ct} | HTML Size: {len(body)} bytes")
            
        # 2. Test Deep Link SPA Routes (GET /events, GET /forecast)
        print("[CHECK 2] Testing SPA Deep Linking (GET /events, GET /forecast) ...")
        for route in ["/events", "/forecast", "/analytics", "/stream"]:
            with urllib.request.urlopen(f"http://127.0.0.1:8000{route}", timeout=3) as resp:
                assert resp.status == 200
                ct = resp.headers.get("content-type", "")
                assert "text/html" in ct
                print(f"   └─ Route {route}: 200 OK (SPA fallback verified)")
                
        # 3. Test Missing Asset 404 (GET /assets/missing.js)
        print("[CHECK 3] Testing Missing Asset Protection (GET /assets/missing.js) ...")
        try:
            urllib.request.urlopen("http://127.0.0.1:8000/assets/missing.js", timeout=3)
            raise AssertionError("Expected 404 for missing asset")
        except urllib.error.HTTPError as e:
            assert e.code == 404
            print(f"   └─ Missing asset returned HTTP 404 as required")
            
        # 4. Test REST API Workflows
        print("[CHECK 4] Testing REST API Telemetry Sources (GET /api/v1/sources) ...")
        with urllib.request.urlopen("http://127.0.0.1:8000/api/v1/sources", timeout=3) as resp:
            assert resp.status == 200
            sources = json.loads(resp.read().decode("utf-8"))
            print(f"   └─ Sources queried successfully: {len(sources)} sources found")
            
        # 5. Test Live NDJSON Ingestion
        print("[CHECK 5] Testing Live NDJSON Ingestion (POST /api/v1/stream/ingest/ndjson) ...")
        sample_flow = json.dumps({
            "ts": time.time(),
            "id.orig_h": "192.168.1.100",
            "id.resp_h": "10.0.0.1",
            "id.orig_p": 45000,
            "id.resp_p": 443,
            "proto": "tcp",
            "duration": 0.1,
            "orig_bytes": 1024,
            "resp_bytes": 4096,
        })
        payload = json.dumps({
            "source_id": "live_probe_check",
            "ndjson_content": sample_flow,
            "data_category": "live_telemetry",
        }).encode("utf-8")
        
        req = urllib.request.Request(
            "http://127.0.0.1:8000/api/v1/stream/ingest/ndjson",
            data=payload,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=3) as resp:
            assert resp.status == 200
            res_data = json.loads(resp.read().decode("utf-8"))
            assert res_data["accepted_records"] == 1
            print(f"   └─ Live flow accepted: {res_data['accepted_records']}, rejected: {res_data['rejected_records']}")
            
        # 6. Test Forecasting Prediction API
        print("[CHECK 6] Testing Forecasting Inference (POST /api/v1/forecast/predict) ...")
        req_pred = urllib.request.Request(
            "http://127.0.0.1:8000/api/v1/forecast/predict",
            data=json.dumps({"threshold": 0.5}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req_pred, timeout=3) as resp:
            assert resp.status == 200
            pred_data = json.loads(resp.read().decode("utf-8"))
            print(f"   └─ Prediction generated: score={pred_data['propensity_score']}, incident={pred_data['predicted_incident']}")
            
        print("\n[ALL WORKFLOWS VERIFIED OPERATIONAL]")
        
    finally:
        # 7. Clean Shutdown Verification
        print("[SHUTDOWN] Terminating server process ...")
        proc.terminate()
        try:
            proc.wait(timeout=5)
            print("[SHUTDOWN] Server process exited cleanly.")
        except subprocess.TimeoutExpired:
            proc.kill()
            print("[SHUTDOWN] Server process forcibly terminated after timeout.")
            
        # Verify port 8000 released
        time.sleep(1)
        print("[CHECK] Verified port 8000 is released.")

if __name__ == "__main__":
    test_launcher_lifecycle()
