# Contributing safely

## Never commit private device data

Never commit real security-key serial numbers, OTPs or OTP public IDs, PINs, access codes, cryptographic keys, raw private captures, internal URLs, employee information, or personal machine paths. Do not commit screenshots, logs, packet captures, or binaries that embed those values.

Use deterministic synthetic fixtures from `tests/fixtures/`. A literal Modhex fixture is allowed only inside that directory when one of the first five lines says `SYNTHETIC TEST DATA — NOT FROM A REAL DEVICE`. This narrow exception does not bypass other secret scanning.

## Run checks locally

```powershell
python -m pip install pre-commit
pre-commit install
pre-commit run --all-files
python scripts/check-sensitive-data.py
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

Store raw local research under `%LOCALAPPDATA%\ZukeyLab\private\`, never in the repository. Before sharing diagnostics, use **Copy sanitized diagnostics** and inspect the result yourself.
