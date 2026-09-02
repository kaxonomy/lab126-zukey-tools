# Publication checklist

Do not push until every required local check is complete and the rewritten refs have been reviewed.

## Completed locally

- [x] External pre-sanitization bundle created and verified outside the repository.
- [x] Baseline tests, headless device discovery, build, and visible-window launch recorded.
- [x] Real device serial, OTP public ID, personal path, and captured evidence removed from the publication tree.
- [x] Private `work/` tree moved outside the repository and ignored.
- [x] Synthetic OTP/serial helpers replace captured test values.
- [x] Logs, copied diagnostics, and headless exports use the shared redaction layer.
- [x] Custom scanner, gitleaks pre-commit hook, and CI workflow added.
- [x] Unit tests and packaging pass after sanitization.
- [x] Scanner negative tests reject OTP, private-key, and serial-shaped samples.
- [x] A fresh clean root replaces the original published root.
- [x] All publication refs and reachable objects were rescanned.

## User review before publication

- [ ] Inspect `git status`, `git log --all --decorate --oneline`, `git branch -a`, and `git tag -n`.
- [ ] Run the elevated headless GetInfo check after approving UAC; inspect only sanitized output.
- [ ] Optionally perform a live touch capture and confirm only a redacted value reaches diagnostics.
- [ ] Review `THIRD_PARTY_NOTICES.md`, especially transitive components included by `imgui-bundle`.
- [ ] Rotate or revoke any reusable secret discovered independently of this report. No reusable secret was confirmed by this sanitization pass.
- [ ] Approve the explicit force-with-lease commands from the final report.

Rewriting GitHub history does not erase forks, clones, caches, pull requests, Actions logs, or previously downloaded copies. Contact GitHub Support if cached sensitive objects require platform-side removal.
