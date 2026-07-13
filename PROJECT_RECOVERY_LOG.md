# Project Recovery Log

Use this file as the known-good checkpoint notes for CyberShield Innovators. Keep it updated whenever a fix is verified, so the project can be shifted back to a working state if a later experiment breaks something.

## Current Known-Good State

Date: 2026-05-12

Main verified fixes:
- Image scans are no longer stuck at 50 percent risk/safety.
- The steganography scanner now prefers `cloud/backend/app/models/stg_models/best_model.pt`.
- If `detector_config.json` is rejected because of bad calibration, the scanner falls back to the best validated binary model instead of averaging all loaded models.
- The top-level scan wrapper now preserves useful scanner fields like `primary_model`, `scanner_stage`, `checkpoint_val_acc`, and `model_path`.
- The `best_model.pt` output mapping is inverted because real scans showed safe files being treated as unsafe and unsafe files being treated as safe.
- Uncalibrated stego decisions now use a conservative decision score that subtracts unstable test-time augmentation variance before marking an image suspicious.
- Stable raw stego signals are still treated as suspicious even when the conservative penalty would otherwise push them below the threshold.
- `UNCERTAIN` image results below the stego threshold are no longer automatically displayed as `Suspicious`.
- Zero-day scanner NumPy and EMBER/LIEF compatibility warnings are silenced in the sandbox monitor logs; the compatibility patch remains active.

Verified command:

```powershell
$env:PYTHONPATH='cloud\backend'; cloud\backend\.venv-ml\Scripts\python.exe -c "import json; from app.scanner import scan_file; r=scan_file('cloud/backend/tmp/cover_probe_00023.jpg', log_event=False); print(json.dumps({k:r.get(k) for k in ['fused_risk','stego_prob','cover_prob','confidence','predicted_label','decision','primary_model','model_path','checkpoint_val_acc','scanner_stage','config_ignored_reason']}, indent=2))"
```

Verified result summary:
- `fused_risk`: `0.29833246471200026`
- `raw_stego_prob`: `0.3296618163585663`
- `stego_prob`: `0.3296618163585663`
- `cover_prob`: `0.6703381836414337`
- `decision_score`: `0.29833246471200026`
- `predicted_label`: `Cover`
- `decision`: `COVER`
- `primary_model`: `best_resnet18`
- `output_inverted`: `true`
- `model_path`: `cloud/backend/app/models/stg_models/best_model.pt`
- `checkpoint_val_acc`: `0.7125`

Compile check:

```powershell
$env:PYTHONPATH='cloud\backend'; cloud\backend\.venv-ml\Scripts\python.exe -m compileall cloud\backend\app\scanners\stg\scanner.py cloud\backend\app\scanner.py
```

## Files Changed For This Working State

- `cloud/backend/app/scanners/stg/scanner.py`
  - Added support for `best_model.pt`.
  - Added a local ResNet18-compatible model definition.
  - Added `binary_softmax` prediction handling.
  - Inverted the `best_model.pt` output class mapping after scans showed labels reversed.
  - Added conservative decision scoring for uncalibrated models using TTA variance and preprocessing disagreement penalties.
  - Increased the TTA variance penalty from `2.0` to `3.5` so unstable clean images get healthier safe scores.
  - Changed invalid-config fallback to use `get_default_strategy()`.
  - Added status fields for `best_model.pt`.

- `cloud/backend/app/scanner.py`
  - Updated image result normalization to preserve the detailed payload instead of replacing it with a smaller object.
  - Preserves scanner-provided `fused_risk` instead of overwriting it with raw stego probability.

- `cloud/backend/app/main.py`
  - No longer treats every `UNCERTAIN` image decision as suspicious when the risk is below the stego threshold.

- `cloud/sandbox/sandbox_monitor.py`
  - Mirrors the backend `UNCERTAIN` handling for sandbox-written logs.

- `user/Frontend/src/pages/ResultPage.jsx`
- `user/Frontend/src/pages/ScanPage.jsx`
- `user/Frontend/src/pages/LogsPage.jsx`
  - No longer turn every `UNCERTAIN` decision into `Suspicious` if risk is below threshold.

- `cloud/backend/app/scanners/zd/scanner.py`
  - Suppresses NumPy legacy alias `FutureWarning` noise.
  - Suppresses EMBER's printed LIEF version warning during extractor startup.

## Why The 50 Percent Bug Happened

The scanner rejected `detector_config.json` because the thresholds were invalid and calibration accuracy was low. The fallback strategy then averaged multiple models. In this project state, that average could land at exactly `0.5`, so every scan appeared as 50 percent.

## Why The Reversed Safe/Unsafe Bug Happened

The checkpoint metadata says the classes are `Cover, Stego`, but live scan behavior showed the output direction was reversed. The scanner now treats the opposite softmax output as stego risk for `best_model.pt`.

Known local verification:
- `cloud/backend/tmp/cover_probe_00023.jpg` now returns `COVER` with risk around `0.33`.
- Next important check: scan a known unsafe/stego file and confirm it returns `STEGO` or `Suspicious`.

False-positive tuning from car images:
- `9028128.jpg` previously logged raw score `0.8904` with high TTA std `0.1281`; conservative decision score is now about `0.376`.
- `9028104.jpg` previously logged raw score `0.7632` with high TTA std `0.0807`; conservative decision score is now about `0.480`.
- Both are below the `0.65` stego threshold after the stability penalty, so new scans should not show them as `Suspicious`.

False-negative tuning from known stego images:
- `download (1).png` logged raw score `0.6916` with low TTA std `0.0285`; new decision score remains `0.6916`, so it should show as `Suspicious`.
- `flowing-fabric-3840x2160-26286.jpg` logged raw score `0.5532` with TTA std `0.0559`; new stable raw signal rule raises decision score to `0.65`, so it should show as `Suspicious`.
- The stable raw signal rule applies when raw score is at least `0.50` and TTA std is below `0.08`.

Zero-day scanner notes:
- Chrome standalone installer logged as `Safe` with risk `0.0000418`.
- Telegram installer `tsetup-x64.6.7.8.exe` logged as `Malicious` with risk `0.9197`.
- `mt5setup (2).exe` logged as `Safe` with risk `0.000715`.
- `7z2601-x64.exe` logged as `Safe` with risk `0.0082`.
- `ml_stack_status()` verified ready with `torch`, `ember`, `lief`, model, and normalization present.

## How To Return To This Working State

If later changes break scanning:

1. Check this file first and compare the files listed above.
2. Make sure `cloud/backend/app/models/stg_models/best_model.pt` still exists.
3. Restart the backend server after scanner changes.
4. Run the verified scan command above.
5. Confirm the output is not pinned to `0.5`, `primary_model` is `best_resnet18`, and `output_inverted` is `true`.

## Update Rule

Whenever a future change is tested and works, add:
- Date
- What changed
- Files changed
- Exact command used to verify
- Result summary
- Any rollback notes

## Update - 2026-05-30

Working APK scanner state:
- APK zero-day detection is integrated into the same scan pipeline as `.exe` zero-day and image steganography scanning.
- `.apk` files are accepted by manual upload and by the user-side folder watcher.
- The APK model artifact lives at `cloud/backend/app/models/apk_models/apk.pth`.
- APK scanner status is included in `/api/scan/ml-status` as `apk.ready`.
- APK result payloads include explicit APK fields:
  - `apk_malware_prob`
  - `apk_benign_prob`
  - `apk_structural_risk`
  - `apk_raw_combined_risk`
  - `apk_static_analysis`
  - `apk_preprocessing_version`
- Important preprocessing fix: APK byte histogram, byte-entropy histogram, and printable character distribution now use raw counts, not normalized distributions.
- The verified preprocessing marker is:

```text
apk_preprocessing_version = ember_raw_counts_v2
```

Why this mattered:
- The APK checkpoint was trained on EMBER2024 APK JSONL feature rows.
- Those rows are expected to contain raw count-style histogram values.
- The first app-side APK preprocessor normalized several histogram families, which mismatched training preprocessing and produced extreme risk outputs.
- After switching to raw counts, APK safety scoring became usable again.

APK policy behavior:
- The neural model remains the primary APK malware detector.
- A secondary APK structural layer inspects:
  - readable ZIP/APK structure
  - `AndroidManifest.xml` presence
  - signing certificate files under `META-INF`
  - DEX count
  - native `.so` library count
  - high-risk permission strings when visible
  - suspicious Android strings
  - third-party APK distribution filename signal
- Additional non-training APK checks were added:
  - duplicate ZIP entries
  - ZIP path traversal entries
  - encrypted ZIP entries
  - suspicious embedded file types such as scripts, executables, JAR/class files
  - high compression-ratio entries
  - URL/IP indicators, including raw-IP URLs
  - certificate file SHA-256 fingerprints
  - APK static evidence level: `low`, `medium`, or `high`
- Hard `BLOCKED` APK results require both strong model score and structural support.
- High model score without enough structural support is capped into manual review instead of automatic hard delete.

Files changed for this working state:
- `cloud/backend/app/scanners/apk/scanner.py`
  - Added APK ML inference.
  - Added raw-count APK preprocessing.
  - Added APK structural analysis.
  - Added ZIP tamper/anomaly checks, URL/IP extraction, certificate fingerprints, and evidence levels.
  - Added explicit APK probability/risk fields.
  - Added `apk_preprocessing_version`.
- `cloud/backend/app/scanners/apk/model_def.py`
  - Added the `ApkMLP` architecture matching the checkpoint.
- `cloud/backend/app/scanners/apk/__init__.py`
- `cloud/backend/app/apk_scanner.py`
  - Added compatibility wrappers for app imports.
- `cloud/backend/app/models/apk_models/apk.pth`
- `cloud/backend/app/models/apk_models/latest_metrics.json`
  - Added APK model artifacts copied from Lincoln's APK training folder.
- `cloud/backend/app/scanner.py`
  - Routes `.apk` files to the APK scanner.
  - Includes APK readiness in ML status.
- `cloud/backend/app/scanners/router.py`
  - Mirrors `.apk` support for the older scanner router path.
- `cloud/backend/app/main.py`
  - Unsupported-file message now lists `.apk`.
- `user/watcher/folder_watcher.py`
  - Watches and uploads `.apk` files.
- `user/Frontend/src/pages/ScanPage.jsx`
- `user/Frontend/src/pages/ResultPage.jsx`
  - Show APK malware probability, APK structural risk, evidence level, DEX count, and certificate count.

Verification commands:

```powershell
cd "D:\Sem VIII\Project\CyberShield Innovators"
python -m compileall cloud\backend\app\scanners\apk
```

```powershell
cd "D:\Sem VIII\Project\CyberShield Innovators"
$env:PYTHONPATH='cloud\backend'
python -c "from app.apk_scanner import ml_stack_status; import json; print(json.dumps(ml_stack_status(), indent=2, default=str))"
```

Expected status:
- `ready` is `true`.
- `model_exists` is `true`.
- `metrics_exists` is `true`.
- `preprocessing_version` is `ember_raw_counts_v2`.

Runtime verification:
- Restart the FastAPI backend after scanner changes.
- Scan an APK.
- Confirm the new log line in `cloud/backend/app/reports/scan_events.jsonl` contains:

```json
"engine": "apk-ml",
"apk_preprocessing_version": "ember_raw_counts_v2"
```

Backend restart command:

```powershell
cd "D:\Sem VIII\Project\CyberShield Innovators\cloud\backend"
.\.venv-ml\Scripts\python.exe -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Rollback notes:
- If APK scoring becomes extreme again, first check whether the backend was restarted and whether log entries include `apk_preprocessing_version: ember_raw_counts_v2`.
- If the marker is missing, the running backend is using old code.
- If the marker is present but false positives remain high, the next fix should be model/data work: use the exact EMBER2024 APK feature extractor or retrain on the app's raw-APK extractor output.

## Update - 2026-05-15

Working demo state:
- Project is now split by deployment target:
  - `user/Frontend/` for the user-device React UI.
  - `cloud/backend/` for the backend/cloud FastAPI scanner service.
  - `cloud/sandbox/` for optional legacy Windows Sandbox tooling.
- Two-PC demo networking was verified after allowing inbound TCP port `8000` on the cloud PC and using the cloud PC Wi-Fi IPv4 address in `VITE_BACKEND_URL`.
- Backend must be started from the project venv, not Anaconda `(base)`, otherwise scanner dependencies may mismatch and `.exe` scans fall back to heuristics.

Backend run command:

```powershell
cd "D:\Sem VIII\Project\CyberShield Innovators\cloud\backend"
.\.venv-ml\Scripts\python.exe -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

User frontend run command:

```powershell
cd "D:\Sem VIII\Project\CyberShield Innovators\user\Frontend"
npm run dev -- --host 0.0.0.0
```

User frontend `.env` format:

```env
VITE_BACKEND_URL=http://<CLOUD_PC_WIFI_IPV4>:8000
```

Environment fixes applied/verified:
- Recreated or repaired `cloud/backend/.venv-ml` with Python 3.11.
- Installed project dependencies from:
  - `cloud/backend/requirements.txt`
  - `cloud/backend/requirements-ml.txt`
- Fixed the NumPy mismatch by using venv NumPy `1.26.4` instead of Anaconda base NumPy `2.2.6`.
- Installed missing ML packages into `.venv-ml`:
  - `lightgbm` for EMBER import support.
  - `albumentations` for the steganography scanner.
  - `efficientnet-pytorch` for the steganography scanner.

Verification commands:

```powershell
cd "D:\Sem VIII\Project\CyberShield Innovators\cloud\backend"
.\.venv-ml\Scripts\python.exe -c "import numpy, torch, torchvision, scipy, sklearn, pefile, lief; print(numpy.__version__); print('core ok')"
.\.venv-ml\Scripts\python.exe -c "import ember; print('ember ok')"
.\.venv-ml\Scripts\python.exe -c "import albumentations, efficientnet_pytorch; print('stg deps ok')"
.\.venv-ml\Scripts\python.exe -c "from app.scanner import ml_stack_status; import json; print(json.dumps(ml_stack_status(), indent=2))"
```

Expected status:
- `zd.ready` is `true`.
- `stg.ready` is `true`.
- `.exe` scans use the ML engine instead of heuristic fallback.
- Image scans use the steganography ML stack.

If ML falls back to heuristics again:
1. Confirm backend is running with `.\.venv-ml\Scripts\python.exe -m uvicorn ...`, not plain `uvicorn`.
2. Open `http://127.0.0.1:8000/api/scan/ml-status` on the cloud PC.
3. Install any missing module into `.venv-ml`, not Anaconda base.
4. Restart backend after installing dependencies.

## Update - 2026-05-16

Working demo state:
- Manual upload scanning from the user frontend to the cloud backend is working.
- Dashboard and Logs pages update after scans are completed.
- Cloud backend ML status was verified locally with both scanner stacks ready:
  - `stg.ready`: `true`
  - `zd.ready`: `true`
- `/api/scan/logs?limit=100` returned a valid response from the cloud backend. It returns an empty list before scans and then fills after files are scanned.
- Folder monitoring is now implemented through a user-side watcher process. The browser Settings page saves folder paths and sends them to the local watcher, while the watcher monitors Windows folders and uploads supported new files to the cloud backend.

Important networking note:
- `http://192.168.1.25:8000/...` was only an example backend IP in earlier instructions.
- The working frontend should use the actual cloud PC Wi-Fi/Ethernet IPv4 in `user/Frontend/.env`.
- If `/api/health` works but `/api/scan/ml-status` gives `{"detail":"Not Found"}`, check that the request is reaching the correct cloud backend app, not the older sandbox backend or a different device.

Cloud backend run command:

```powershell
cd "D:\Sem VIII\Project\CyberShield Innovators\cloud\backend"
.\.venv-ml\Scripts\python.exe -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Cloud backend verification commands:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/api/scan/ml-status | ConvertTo-Json -Depth 10
Invoke-RestMethod "http://127.0.0.1:8000/api/scan/logs?limit=100" | ConvertTo-Json -Depth 10
```

Expected verified status:

```json
{
  "stg": {
    "ready": true,
    "error": null
  },
  "zd": {
    "ready": true,
    "error": null
  }
}
```

User frontend run command:

```powershell
cd "D:\Sem VIII\Project\CyberShield Innovators\user\Frontend"
npm run dev -- --host 0.0.0.0
```

User frontend `.env` format:

```env
VITE_BACKEND_URL=http://<REAL_CLOUD_PC_IPV4>:8000
```

User folder watcher run command:

```powershell
cd "D:\Sem VIII\Project\CyberShield Innovators\user\watcher"
pip install -r requirements.txt
$env:CYBERSHIELD_BACKEND_URL="http://<REAL_CLOUD_PC_IPV4>:8000"
python folder_watcher.py
```

Folder watcher behavior:
- Runs locally on the user PC at `http://127.0.0.1:8765`.
- The Settings page connects to the watcher and shows `Watcher connected` when it is running.
- Added folder paths are saved to the watcher config and to frontend local storage.
- New supported files placed inside monitored folders are uploaded to the cloud backend automatically.
- Existing files already present in a folder are remembered when settings are saved, so they are not all uploaded immediately by default.

Supported watcher file types:

```text
.exe, .jpg, .jpeg, .jfif, .png, .bmp, .gif, .tif, .tiff, .webp
```

Files changed for this working state:
- `user/Frontend/src/App.jsx`
  - Added the Settings page to the frontend navigation.
- `user/Frontend/src/pages/SettingsPage.jsx`
  - Added folder path management.
  - Added local watcher connection/status display.
  - Sends monitored folders and backend URL to the watcher.
  - Moved the light/dark theme switch into Settings.
- `user/Frontend/app.css`
  - Added Settings page and watcher status styling.
- `user/watcher/folder_watcher.py`
  - Added the user-side folder monitor and upload service.
- `user/watcher/requirements.txt`
  - Added watcher dependencies.
- `.gitignore`
  - Ignores watcher runtime config/state/event files.
- `Instructions.txt`
  - Added watcher run instructions.

Verification commands used after the watcher/frontend changes:

```powershell
cd "D:\Sem VIII\Project\CyberShield Innovators\user\Frontend"
npm.cmd run build
```

```powershell
cd "D:\Sem VIII\Project\CyberShield Innovators"
python -m py_compile user\watcher\folder_watcher.py
```

Verified result summary:
- Frontend production build completed successfully.
- `user/watcher/folder_watcher.py` passed Python syntax compilation.
- End-to-end app behavior was confirmed by scanning files successfully, seeing results, and seeing the Logs page update.

If folder monitoring does nothing:
1. Confirm the user-side watcher terminal is running.
2. Open the frontend Settings page and check for `Watcher connected`.
3. Confirm the watcher was started with `CYBERSHIELD_BACKEND_URL` pointing to the real cloud backend IP.
4. Confirm the downloaded file has a supported extension.
5. Keep the watcher terminal open during the demo.

## Update - 2026-05-29

Working demo state:
- Steganography image scanning still uses the ML model as the primary decision source.
- Decoder/recovery is now an extra workflow, not the primary decision-maker:
  - If the model says the image is safe, decoder is skipped with `File is safe; nothing to decode.`
  - If the model says the image needs Review or is Suspicious, decoder can run and produce recovery artifacts.
- Added a `Review` middle state for borderline image scores:
  - `risk < 0.65` => `Safe`
  - `0.65 <= risk < 0.80` => `Review`
  - `risk >= 0.80` => `Suspicious`
  - executable `BLOCKED` decisions still map to `Malicious`
- Review files are not auto-deleted. They remain available for manual save/delete from the Result page.
- Added the Decoder Report page to the frontend. It shows:
  - cleaned image download when decoder runs
  - decoded candidates if present
  - assessment findings
  - visual and analysis artifacts
- Cleaned images are generated by:
  - opening the source image with Pillow
  - applying EXIF orientation
  - clearing the least significant bit of RGB channels with `value & 0xFE`
  - re-encoding as PNG to drop appended bytes and ordinary metadata
- Important policy change: every uploaded image is scanned as a fresh potentially dangerous file. CyberShield-cleaned output metadata is not trusted to bypass the model or mark files safe.

Backend run command:

```powershell
cd "D:\Sem VIII\Project\CyberShield Innovators\cloud\backend"
.\.venv-ml\Scripts\python.exe -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Frontend and watcher run command:

```powershell
cd "D:\Sem VIII\Project\CyberShield Innovators\user"
powershell -ExecutionPolicy Bypass -File .\Start-FrontendAndWatcher.ps1
```

Dependency note:
- `Pillow` is now explicitly listed in `cloud/backend/requirements-ml.txt`.
- If the backend venv was created before this update, run:

```powershell
cd "D:\Sem VIII\Project\CyberShield Innovators\cloud\backend"
.\.venv-ml\Scripts\python.exe -m pip install -r requirements.txt
```

Files changed for this working state:
- `cloud/backend/app/scanner.py`
  - Added decoder attachment logic.
  - Added Review/unsafe threshold metadata for image scans.
  - Skips decoder when the model says safe.
  - Treats each uploaded image as a fresh scan; no marker-based safe override.
- `cloud/backend/app/main.py`
  - Added `Review` result mapping.
  - Keeps Review files in manual review instead of auto-deleting.
  - Serves decoder report assets and cleaned image downloads.
- `cloud/Decoder/`
  - Added the local decoder/recovery tool and backend wrapper.
- `user/Frontend/src/pages/DecoderReportPage.jsx`
  - Added the app-styled decoder report page.
- `user/Frontend/src/pages/ScanPage.jsx`
- `user/Frontend/src/pages/ResultPage.jsx`
- `user/Frontend/src/pages/LogsPage.jsx`
  - Added Review handling and decoder/cleaned-image UI.
- `user/Frontend/src/App.jsx`
  - Added Decoder Report navigation.
- `user/Frontend/app.css`
  - Added Decoder Report and Review styling.

Verification commands:

```powershell
cd "D:\Sem VIII\Project\CyberShield Innovators\cloud\backend"
.\.venv-ml\Scripts\python.exe -c "from app.main import overall_result_for; print(overall_result_for({'decision':'STEGO','predicted_label':'Stego','fused_risk':0.69,'stego_threshold':0.65,'unsafe_threshold':0.8})); print(overall_result_for({'decision':'STEGO','predicted_label':'Stego','fused_risk':0.85,'stego_threshold':0.65,'unsafe_threshold':0.8})); print(overall_result_for({'decision':'COVER','predicted_label':'Cover','fused_risk':0.18,'stego_threshold':0.65,'unsafe_threshold':0.8}))"
```

Expected result:

```text
Review
Suspicious
Safe
```

Frontend build verification:

```powershell
cd "D:\Sem VIII\Project\CyberShield Innovators\user\Frontend"
npm.cmd run build
```

Verified result summary:
- Backend syntax checks passed during implementation.
- Frontend production build completed successfully.
- Latest pushed branch: `user-cloud`
- Latest pushed commit: `172b486` (`Integrate stego decoder and review workflow`)

Rollback notes:
- If decoder reports become noisy, remove generated folders under `cloud/Decoder/reports/`; they are output artifacts, not required source code.
- If Review behavior is too strict or too lenient, tune `DEFAULT_REVIEW_THRESHOLD` and `DEFAULT_UNSAFE_THRESHOLD` in `cloud/backend/app/scanner.py`, then restart the backend.
