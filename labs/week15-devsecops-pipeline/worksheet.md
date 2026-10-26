# Worksheet 15 — DevSecOps: Putting It Together (4 hrs)

> **Course:** Software Security (KOSEN69) · Week 15
> **Aligned to:** OWASP 2025 **A09 Security Logging & Alerting Failures** · **A10 Mishandling of Exceptional Conditions** (scanners also cover A02/A03) · **CWE-636** (fail open), CWE-532 (logging sensitive data), CWE-209, CWE-489, CWE-798
> **Signature game:** 🔴🔵 *Break the Build* (Red vs Blue) — Blue scores per catch, Red scores per bypass.

> ⚠️ **Ethics note:** The pipeline and `sample-service.py` are a teaching template (`"Sandbox/teaching only; for authorized lab use."`). Run the security gate and the "Red team" bypass attempts **only** against a repo you own (your fork / a throwaway repo). Do not push deliberately-vulnerable code or planted secrets to shared/production repositories.

---

## Part 1 — Student Information

| Name | Student ID | Date | Group | AI Tool |
|------|-----------|------|-------|---------|
| Thura Aung | 6631503094 | 25.October.2026 | - | ChatGPT, Claude (VS Code) |

---

## Part 2 — Lecture Questions

Answer in your own words (2–4 sentences each).

1. `README-pipeline.md` says each tool runs **twice** (report step, then gate step). Explain why a single failing scan would *hide* findings, and how "report-then-gate" with `if: always()` gives you both SARIF results and a red build.

In GitHub Actions, when a step exits with an error, the job fails and **every later step is skipped** by default. If the only scan step failed on findings, the next step, which uploads the SARIF file, would never run. You'd get a red X but **no findings in the Security tab**, just a raw log someone has to dig through. Report-then-gate splits the work:
1. The **report step** runs with `|| true` / `exit-code: "0"`, so it always succeeds and writes the SARIF file.
2. The **upload step** has `if: always()`, so it runs even if something before it failed. The findings always reach the Security tab.
3. The **gate step** re-runs the same scan with `--error` / `exit-code: "1"`. It fails the job on HIGH/CRITICAL findings or any secret, so the build turns **red** and a protected branch can't merge.

The result: reviewers see *what* was found, and the pipeline still says **no**.

2. What is the difference between **fail-closed** and **fail-open**? In `sample-service.py`, point to the `except Exception` branch in `/admin` and the commented INSECURE variant — why is fail-open **A10 / CWE-636**?

**Fail-closed** means that when something unexpected goes wrong, the system **denies** access. **Fail-open** means it **allows** access, falling back to the less secure state. In `sample-service.py`, the `except Exception as exc:` branch of `/admin` (L96–103) is fail-closed: it logs `event=authz_error outcome=deny … error=<exception type>` and returns **403**. The commented INSECURE variant (L109–110) is fail-open: `except Exception: return jsonify(secret="the cake is a lie")`, so any error hands over the admin secret. That is **CWE-636 (Not Failing Securely)** and OWASP 2025 **A10 Mishandling of Exceptional Conditions**: an attacker who can *cause* an error gets in without credentials, for example with a missing header, a malformed token or a database timeout. `insecure_service.py` shows exactly this: `USERS[token]` raises `KeyError` when there is no token, and the `except` grants the panel.

3. The `permissions:` block in `security-ci.yml` is `contents: read`, `security-events: write`. Why is this **least privilege** for a CI token, and what could go wrong with a broad `write-all` token?

Every workflow run gets a `GITHUB_TOKEN`. This one only needs to **read the code** (`actions/checkout`) and **write security events** (upload SARIF to code scanning), so those are the only two permissions it gets. It's the same rule as Week 13's IAM policy: only the actions it needs, nothing more. CI runs a lot of third-party code: actions, Docker images such as `semgrep/semgrep:latest`, and the PR's own code. If any of it is malicious or compromised, a `write-all` token would let it **push commits** (a backdoor straight into the code), **create releases or tags**, **publish packages**, delete branches, or edit issues and PRs. This really happens: in March 2025 the popular `tj-actions/changed-files` action was compromised and dumped CI secrets into build logs in thousands of repositories. With `contents: read`, a compromised step can still read the code, but it can't change anything.

4. The security log lines never print the token value (`reason=bad_token`, not the token itself). Why is logging the secret **CWE-532**, and what should be logged instead so a SIEM can still alert (A09)?

Logs are seen by far more people and systems than a secret store: developers, operations staff, the log platform and SIEM vendor, and backups that are kept for years. Writing a token into a log line (**CWE-532, Insertion of Sensitive Information into Log File**) turns the log into a list of valid credentials that anyone with log access can replay. Failed logins are risky too, because a "bad" token is often a real password with a typo. Instead, log **what happened, to whom, from where, and the result**, as structured key=value fields: `event=authn_failure outcome=deny src_ip=… reason=bad_token`, plus a timestamp and `subject` when the user is known. That's enough for a SIEM to alert, for example *"more than 10 `authn_failure` from one `src_ip` in 5 minutes"* (brute force) or repeated `authz_failure reason=not_admin` from one subject (privilege probing). If attempts need to be linked to the same token, log a keyed hash of it, never the value.

5. Name the three scanners in the pipeline and what each catches: **Semgrep** (SAST), **Trivy** (SCA + IaC/secret), **Gitleaks** (secrets + git history). Which OWASP categories does each map to per the README table?

| Scanner | Type | What it catches | Maps to (README table) |
|---------|------|-----------------|------------------------|
| **Semgrep** | SAST | Insecure patterns in our **own source code**, e.g. SQL injection, `eval`, `debug=True`, unsafe deserialization (rulesets `p/default` + `p/owasp-top-ten`) | **OWASP Top 10 rules** |
| **Trivy** | SCA + IaC + secrets | Known-vulnerable **dependencies** (`fs`, `vuln`), **Dockerfile/IaC misconfigurations** (`config`, e.g. DS-0002 running as root) and secrets in files | **A03** (supply chain) / **A02** (misconfiguration) |
| **Gitleaks** | Secret scanning | Hard-coded **tokens, keys and passwords**, including in old commits (`fetch-depth: 0` checks the full git history) | **CWE-798** |

Each scanner covers a gap the others leave: Semgrep reads code logic, Trivy looks at what we depend on and how we deploy, and Gitleaks finds credentials even after someone "deleted" them in a later commit.

---

## Part 3 — Hands-on Lab (180 min in class)

> The task budgets below add up to 205 min. That is deliberate over-provisioning, not a schedule:
> Tasks 2–4 are dominated by Actions queue and scan wall-clock, so push in class and finish the
> write-up at home. Your instructor will say which task runs as homework.

![Two panels: the CI gate in security-ci.yml, where a MEDIUM DS-0001 finding slips past the HIGH,CRITICAL threshold and the build goes green, and the /admin handler, where one except branch returns 200 with the flag while the other returns 403 and logs it.](img/fail-closed.svg)

**Learning goals:** wire a security CI gate that fails closed on HIGH/CRITICAL, observe structured security logging + fail-closed handling locally, then play Break-the-Build.

**Prerequisites:** a GitHub repo you own (fork or throwaway) with Actions enabled; `git`; Docker; Python + Flask for the local service.

### Environment setup (real commands)

```bash
# --- A) Wire the gate into a repo you own (README-pipeline.md §1) ---
mkdir -p .github/workflows
cp labs/week15-devsecops-pipeline/security-ci.yml .github/workflows/security-ci.yml
git add .github/workflows/security-ci.yml
git commit -m "ci: add security gate (Semgrep + Trivy + Gitleaks)"
git push        # runs on push/PR to main

# --- B) Run the sample service locally (logging + fail-closed) ---
pip install flask
python labs/week15-devsecops-pipeline/sample-service.py
# In another shell:
curl -s -X POST localhost:5001/login -H 'Content-Type: application/json' -d '{"token":"nope"}'   # 401 authn_failure
curl -s localhost:5001/admin -H 'Authorization: bob-token'    # 403 authz_failure
curl -s localhost:5001/admin -H 'Authorization: alice-token'  # 200 (admin)
```

**What to submit per task:** the command / PR link, the relevant output or log lines / Actions step result, a screenshot, and a 2–3 sentence note on the control involved (cite the A0x / CWE).

### Task 0 — Onboarding (15 min)
Run the sample service; trigger the three curls above. **Deliverable:** screenshot of the structured `event=...` security log lines for authn_failure, authz_failure, and authz_success.

**Commands (two PowerShell windows):**
```powershell
# Window 1: the service (its security log prints here)
cd C:\software-security\labs\week15-devsecops-pipeline
python sample-service.py

# Window 2: the three requests
Write-Output "$(whoami) | Thura Aung | 6631503094 | $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss K')"
curl.exe -s -X POST localhost:5001/login -H 'Content-Type: application/json' -d '{\"token\":\"nope\"}'
curl.exe -s localhost:5001/admin -H 'Authorization: bob-token'
curl.exe -s localhost:5001/admin -H 'Authorization: alice-token'
```
Python 3.13.5 + Flask 3.0.0 were already installed locally. **Windows note:** the worksheet's `-d '{"token":"nope"}'` returns `400 Bad Request` in Windows PowerShell 5.1, because PowerShell strips the inner double quotes when it calls `curl.exe`, so Flask receives invalid JSON. Escaping them as `{\"token\":\"nope\"}` fixes it. (`curl` alone is an alias for `Invoke-WebRequest`, so `curl.exe` is used.)

![Task 0 – window 2: identity stamp (19:27:17) and the three curl requests with their responses](task0-requests.png)

![Task 0 – window 1: sample-service security log, authn_failure / authz_failure / authz_success at 19:27:18](task0-logs.png)

The two screenshots belong together: the stamp in window 2 reads **2026-10-25 19:27:17**, and the three security log lines in window 1 are timestamped **19:27:18.025 / .263 / .503**. Each line sits next to the Werkzeug access-log line for the same request (`POST /login` 401, `GET /admin` 403, `GET /admin` 200).

| Request | Response | Security log line |
|---------|----------|-------------------|
| `POST /login` `{"token":"nope"}` | `401 {"error":"authentication failed"}` | `level=WARNING logger=security event=authn_failure outcome=deny src_ip=127.0.0.1 reason=bad_token` |
| `GET /admin` `Authorization: bob-token` | `403 {"error":"forbidden"}` | `level=WARNING logger=security event=authz_failure outcome=deny subject=bob src_ip=127.0.0.1 reason=not_admin` |
| `GET /admin` `Authorization: alice-token` | `200 {"secret":"the cake is a lie"}` | `level=INFO logger=security event=authz_success outcome=allow subject=alice src_ip=127.0.0.1` |

Each line is **structured** `key=value` text: `event`, `outcome`, `subject`, `src_ip` and `reason`, with the level, logger and timestamp from the format string. A SIEM can parse these fields and alert on them without regex guesswork. Failures are logged at `WARNING` and successes at `INFO`, all on the dedicated `security` logger, so they can be shipped apart from normal app noise. None of the lines contains the token itself (CWE-532).

### Task 1 — Logging & fail-closed (35 min, A09/A10)
*Goal:* prove fail-closed behavior. *Steps:* read `/admin` in `sample-service.py`; explain why the broad `except Exception` returns **403, not the secret**, and why `type(exc).__name__` (not the message) is logged (CWE-209). Identify the line that would make it fail *open* (the commented INSECURE variant). *Deliverable:* the log lines + a 2–3 sentence explanation of fail-closed vs fail-open.

**Problem: the `except` branch can't be reached with curl.** In `/admin`, `request.headers.get()` and `_VALID_TOKENS.get()` never raise, so no normal request reaches the `except Exception` branch. To prove fail-closed I **forced** an error. A small test script imports `sample-service.py` unchanged, swaps the token store for one whose `.get()` raises `RuntimeError("db timeout: postgres://admin:hunter2@db.internal/users")`, as if the database failed, and calls `/admin` through Flask's test client. The same script probes two logging gaps.

**Command (PowerShell):**
```powershell
Write-Output "$(whoami) | Thura Aung | 6631503094 | $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss K')"
python "$env:TEMP\claude\c--software-security\9adb82e3-1200-4e36-a9e3-7ca300ddbdbd\scratchpad\w15\task1_failclosed.py" sample-service.py
```
Core of the script:
```python
class BrokenStore(dict):                      # simulates the token store failing
    def get(self, *a, **k):
        raise RuntimeError("db timeout: postgres://admin:hunter2@db.internal/users")

svc._VALID_TOKENS = BrokenStore()
client.get("/admin", headers={"Authorization": "alice-token"})   # a VALID admin token
```

![Task 1 – forced RuntimeError in /admin returns 403 and logs only error=RuntimeError; malformed JSON and spoofed X-Forwarded-For probes, with identity stamp](task1-failclosed.png)

| Test | Response | Security log line |
|------|----------|-------------------|
| Forced `RuntimeError` in `/admin`, with alice's **valid** admin token | `403 {"error":"forbidden"}` | `event=authz_error outcome=deny src_ip=127.0.0.1 error=RuntimeError` |

**Why it returns 403, not the secret (fail-closed):** the `except Exception as exc:` branch (L96–103) does one thing whatever went wrong: it logs `outcome=deny` and returns 403. The code never reaches `return jsonify(secret=…)` unless every check *succeeded*, so an error can only lead to "deny". Even a real admin is refused while the store is broken. That is the deliberate trade-off: a short outage is better than an open door.

**Why `type(exc).__name__` and not the message (CWE-209):** the exception *message* can contain internal details, here a database URL **with a password**. The log line shows only `error=RuntimeError`, and the client sees only `{"error":"forbidden"}`. The fake `hunter2` password appears in neither. The type name is enough to alert on and debug from, and it leaks nothing to the client or to everyone who can read the logs (also CWE-532).

**The line that would make it fail open:** the commented INSECURE variant, L109–110:
```python
# except Exception:
#     return jsonify(secret="the cake is a lie")   # <-- A10 / CWE-636!
```
With that `except`, the same forced error would hand the secret to *anyone*, logged-in or not, and log nothing. Task 1b shows this live in `insecure_service.py`.

**Fail-closed vs fail-open:** a fail-closed system treats "I couldn't check" the same as "no" and denies access. A fail-open system treats it as "yes". Fail-open turns *any* bug, timeout or malformed input an attacker can trigger into an authentication bypass (A10 / CWE-636), so security checks must fail closed and log the denial for A09 alerting.

**Two logging gaps I found with the same script (A09):**

| Probe | Result | Problem |
|-------|--------|---------|
| `POST /login` with malformed JSON `{token:nope}` | `400 Bad Request`, **no security log line** | `request.json` raises before the route logs anything, so broken login attempts never reach the SIEM. |
| `GET /admin` with `X-Forwarded-For: 10.9.9.9 event=authz_success outcome=allow` | Log: `event=authz_failure outcome=deny subject=bob src_ip=10.9.9.9 event=authz_success outcome=allow reason=not_admin` | `_client_ip()` trusts a header the client controls (CWE-348). The attacker picks their own `src_ip`, which defeats per-IP alerting, and **injects fake `key=value` fields** into the log (CWE-117). A parser that takes the last `event=` would read a failure as a success. **Fix:** only trust `X-Forwarded-For` from a known proxy, and escape or quote logged values. |

### Task 1b — Break the Build, live (25 min, A10 / CWE-636)
*Goal:* exploit a real fail-open, then prove the fix. *Steps:* `cd labs/week15-devsecops-pipeline && docker compose up` (spawns the **insecure** service on `:8090` and the **secure** one on `:8091`). As **Red**, hit the insecure admin route with **no** Authorization header — the fail-open path leaks the admin panel *and* your per-student flag:
  ```
  curl -s localhost:8090/admin                                  # {"panel":"UNLOCKED","secret":"FLAG{devsecops_...}"}  <- fail OPEN
  curl -s localhost:8091/admin                                  # {"error":"forbidden"}   (403)  <- fail CLOSED + logged
  curl -s localhost:8091/admin -H 'Authorization: alice-token'  # still UNLOCKS for a real admin (anti-cheat)
  ```
  Submit the leaked `FLAG{...}`. *Deliverable:* the flag, the two contrasting `/admin` responses (`:8090` leak vs `:8091` deny), and the exact line in `insecure_service.py` that fails open. *(The instructor auto-grader re-runs these exploits against your hardened box — you pass only if every bypass is blocked **and** a valid admin token still works.)*

**Commands (PowerShell):**
```powershell
cd C:\software-security\labs\week15-devsecops-pipeline
docker compose up -d
Write-Output "$(whoami) | Thura Aung | 6631503094 | $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss K')"
curl.exe -s localhost:8090/admin                                   # Red: no Authorization header
curl.exe -s localhost:8090/admin -H 'Authorization: x'             # Red: bogus token
curl.exe -s localhost:8091/admin                                   # same attack on the secure service
curl.exe -s localhost:8091/admin -H 'Authorization: alice-token'   # a real admin still works
docker compose logs secure-service | Select-String 'logger=security'
docker compose logs insecure-service | Select-String 'GET /admin'
```

![Task 1b – :8090 leaks the admin panel and flag with no token, :8091 denies with 403 and logs it, alice-token still unlocks; service logs, with identity stamp](task1b-exploit.png)

*(Timestamps inside the container logs are UTC, so they read 7 hours earlier than my +07:00 stamp.)*

**Leaked flag:** `FLAG{devsecops_fail_open_leaks_admin}`. This is the lab's **default** value: `docker-compose.yml` reads `FLAG_DEVSECOPS` from a per-student `.env` (`seed_flags.py`), and none was provided to me (see Evidence & Integrity).

| Request | Insecure `:8090` | Secure `:8091` |
|---------|------------------|----------------|
| No `Authorization` header | **`200 {"panel":"UNLOCKED","secret":"FLAG{devsecops_fail_open_leaks_admin}"}`**, fail **OPEN** | `403 {"error":"forbidden"}`, fail **CLOSED** |
| Bogus token `x` | **`200` panel UNLOCKED + flag** | `403 {"error":"forbidden"}` |
| `bob-token` (valid user, not an admin)* | `403 {"error":"forbidden"}` | `403 {"error":"forbidden"}` |
| `alice-token` (admin) | `200` panel UNLOCKED | `200` panel UNLOCKED: the real admin still works |
| **Security log** (screenshot) | **nothing**, only two Werkzeug access lines `"GET /admin HTTP/1.1" 200`, so the bypass looks like a normal success | `event=authz_failure outcome=deny src_ip=172.22.0.1 reason=unauthenticated` and `event=authz_success outcome=allow subject=alice src_ip=172.22.0.1` |

\*The bob row, the bogus token on `:8091`, and `alice-token` on `:8090` were checked in an earlier test run and aren't in the screenshot. There, `:8091` also logged `reason=unauthenticated` for the bogus token and `subject=bob … reason=not_admin` for bob. The stamp (19:33:27 +07:00) and the container log lines (12:33:27 UTC) are the same second.

**The exact lines in `insecure_service.py` that fail open:**
- **L42** `user = USERS[token]`: dict indexing raises `KeyError` for a missing or unknown token. This is the trigger.
- **L46–49** `except Exception:` → **`return jsonify(panel="UNLOCKED", secret=SECRET)`** (L49): the error handler *grants* access instead of denying it. **This is the line that fails open** (A10 / CWE-636). There is also no logging here (A09), so the bypass is silent.

The result is backwards: a real but unprivileged user (bob) is refused, while someone with **no account at all** gets the admin panel, because "no token" causes an exception and exceptions unlock the door.

**The fix in `secure_service.py`:**
1. `USERS.get(token)` (L47) returns `None` instead of raising, so "no token" becomes a normal, explicit `403` path that is logged with `reason=unauthenticated`.
2. The `except` (L69–76) **denies and logs** `event=authz_error … error=<type>`, so even a real unexpected error fails closed.
3. Every outcome is logged on the `security` logger, so a SIEM can alert on a burst of `authz_failure` from one address.

This meets the auto-grader's rule: every bypass is blocked, and a valid admin token still works.

### Task 2 — Stand up the gate (35 min)
*Goal:* get the workflow running. *Steps:* push `security-ci.yml`, open the Actions run, confirm the three jobs (`semgrep`, `trivy`, `gitleaks`) execute and SARIF appears in the Security tab. *Deliverable:* screenshot of the Actions run + the Code scanning alerts page.

**Repo used:** **https://github.com/ThuraAung6631503094/week15-devsecops-gate**, a new public throwaway repo I own. My course fork already runs the course's own `security-ci`, which is tuned to skip the deliberately vulnerable `labs/`. The lab template would scan every lab and never go green, so it couldn't be used for Task 3. The repo is public because SARIF upload to the Security tab is free only for public repos.

**What I pushed (commit `c06bec4`), with the lab files exactly as provided:**
```text
.github/workflows/security-ci.yml   <- labs/week15-devsecops-pipeline/security-ci.yml, unmodified
app.py                              <- labs/week15-devsecops-pipeline/secure_service.py, unmodified
requirements.txt                    flask==3.1.3
Dockerfile                          python:3.12-slim, non-root USER 65532:65532
README.md
```
```powershell
cd C:\week15-devsecops-gate
git init -b main; git add -A
git commit -m "ci: add security gate (Semgrep + Trivy + Gitleaks) - lab template as provided"
git remote add origin https://github.com/ThuraAung6631503094/week15-devsecops-gate.git
git push -u origin main
```

**Run #1:** https://github.com/ThuraAung6631503094/week15-devsecops-gate/actions/runs/40195272957, result **failure**.

![Task 2 – Actions run #1: Semgrep gate fails after uploading SARIF, Trivy job cannot resolve its action, Gitleaks passes, with identity stamp](task2-run1.png)

![Task 2 – Security tab, Code scanning alerts from the Semgrep SARIF upload, with identity stamp](task2-alerts.png)

| Job | Result | Step by step |
|-----|--------|--------------|
| **SAST (Semgrep)** | ❌ failure | `Semgrep scan -> SARIF` ✅ → `Upload Semgrep SARIF` ✅ → **`Gate — fail on Semgrep findings` ❌** |
| **SCA + IaC (Trivy)** | ❌ failure | **`Set up job` ❌**: *"Unable to resolve action `aquasecurity/trivy-action@0.24.0`, unable to find version `0.24.0`"*, so no scan ran |
| **Secrets (Gitleaks)** | ✅ success | scan ✅ → SARIF upload ✅ → gate ✅ (no secrets) |

**What this run shows:**
1. **Report-then-gate works (Part 2 Q1).** Semgrep's gate failed, but its SARIF was uploaded first, so the **12 findings appear in the Security tab** under Code scanning, not only in a log:
   - **11 × `github-actions-mutable-action-tag`:** every `uses:` line in the lab's **own workflow** pins an action by a movable tag (`@v4`, `@v3`, `@0.24.0`) instead of a commit SHA. **The security gate fails its own code.**
   - **1 × `avoid_app_run_with_bad_host`:** `app.run(host="0.0.0.0")` in `app.py` (line 81).
2. **The movable-tag risk is real, not theory.** The Trivy tag `0.24.0` the template uses **no longer exists** in `aquasecurity/trivy-action` (only `v0.24.0` and newer `v…` tags do), so GitHub couldn't even load the action and the SCA/IaC scans silently didn't happen. A tag can be moved or deleted at any time, and whatever it points to runs with the job's token. Pinning to a full commit SHA prevents both.
3. **GitHub's warnings:** `actions/checkout@v4` and `github/codeql-action/upload-sarif@v3` run on the deprecated Node.js 20, and *"CodeQL Action v3 will be deprecated in December 2026"*. Task 3 moves to the current versions.
4. Gitleaks scanned the full history (`fetch-depth: 0`) and found no secrets, as expected for a clean repo.

All three jobs started, and two of them uploaded SARIF. The template doesn't work out of the box, which is what Task 3 fixes.

### Task 3 — Blue team: pass the gate (30 min)
*Goal:* a green build. *Steps:* ensure the protected repo has no HIGH/CRITICAL findings and no secrets; fix or justify-and-document any (no blanket-ignore, per README §4). *Deliverable:* link to the passing run.

**Passing run (#2):** **https://github.com/ThuraAung6631503094/week15-devsecops-gate/actions/runs/40195823117**, result **success**, commit `64f3f3b`.

Each of the 12 findings and the broken Trivy job from Task 2 was **fixed in code**. Nothing was ignored or suppressed (README §4: "Do not blanket-ignore").

| Finding (run #1) | Fix (commit `64f3f3b`) | Why it is the right fix |
|------------------|------------------------|-------------------------|
| 11 × `github-actions-mutable-action-tag` in `security-ci.yml` | Every `uses:` pinned to a **full commit SHA**, with the version as a comment: `actions/checkout@fbc6f399…  # v5`, `github/codeql-action/upload-sarif@9b325408…  # v4`, `aquasecurity/trivy-action@ed142fd0…  # v0.36.0` | A SHA can't be moved or deleted, so the code that runs with our CI token is exactly the code that was reviewed. This is the same rule as pinning images by digest in Week 13. I also moved to the current major versions, which removed GitHub's "Node.js 20 is deprecated" and "CodeQL Action v3 will be deprecated" warnings. |
| Trivy job: `Unable to resolve action aquasecurity/trivy-action@0.24.0` | Pinned to the SHA of the current release `v0.36.0`. The tag `0.24.0` no longer exists; only `v0.24.0` and newer `v…` tags do | Without this, the SCA and IaC scans never ran at all. The gate was **silently missing two of its scanners**. |
| `avoid_app_run_with_bad_host`: `app.run(host="0.0.0.0")` (`app.py:81`) | `app.run(host=os.environ.get("APP_HOST", "127.0.0.1"), …)`; the `Dockerfile` sets `ENV APP_HOST=0.0.0.0` | The safe default is localhost only. The service listens on all interfaces only inside the container, where it has to so the published port works. I checked locally: the container still returns `200` for `alice-token` and `403` without a token. |

Before pushing, I ran all four gate commands locally with Docker (Semgrep `--error`, Trivy `fs` and `config` with `--exit-code 1`, and Gitleaks `detect --exit-code 1`), and all of them passed.

![Task 3 – Actions run #2: all three jobs and every gate step green, with identity stamp](task3-green.png)

![Task 3 – Code scanning after the fix: 12 Semgrep alerts closed, 1 Trivy LOW alert (DS-0026, no HEALTHCHECK) open, with identity stamp](task3-closed.png)

**Code scanning after run #2: 1 Open, 12 Closed.** All 12 Semgrep alerts were closed automatically as *fixed* when the next analysis no longer found them. One **new** alert opened: **"No HEALTHCHECK defined"**, **Low**, Trivy, `Dockerfile:1` (DS-0026). It appears even though the Trivy steps say `severity: HIGH,CRITICAL`, because `trivy-action` writes **every** severity into SARIF unless `limit-severities-for-sarif: true` is set. I checked the action's own `action.yaml` at the pinned SHA. So the **report** shows everything, while the **gate** blocks only HIGH/CRITICAL. That is a good split: reviewers see the low-risk issues without them blocking merges.

**Triage of the LOW alert (README §4: justified and documented, not ignored):** accepted for now. It is below the HIGH/CRITICAL gate, and health checking is usually the orchestrator's job (e.g. a Kubernetes liveness probe). The `python:3.12-slim` image has no `curl`, so the fix would be a Python-based check: `HEALTHCHECK CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8091/')"`. I'm keeping it open in the Security tab as the reminder, not dismissing it.

| Job | Run #1 (template as provided) | Run #2 (Blue fixes) |
|-----|-------------------------------|---------------------|
| SAST (Semgrep) | ❌ 12 findings | ✅ scan → SARIF → upload → **gate passed** |
| SCA + IaC (Trivy) | ❌ action could not be resolved, nothing scanned | ✅ fs SARIF + config SARIF uploaded → **SCA gate passed**, **IaC gate passed** |
| Secrets (Gitleaks) | ✅ | ✅ |
| **Build** | 🔴 failure | 🟢 **success** |

### Task 4 — Red team: Break the Build (40 min)
*Goal:* make the gate say **no**. *Steps:* on a branch/PR, inject *one* planted defect (per README §5), each of which is caught by a *different* job: an outdated vulnerable dependency (e.g. an old `urllib3`) → Trivy SCA; a Dockerfile that runs as **root** — drop the `USER` line, or write `USER root` → Trivy config (`DS-0002`, HIGH); or a hard-coded token → Gitleaks. Open the PR and watch the matching gate step fail. *Deliverable:* screenshot of the **failing** gate step + which job caught it (Trivy SCA / Trivy config / Gitleaks) and which `exit-code: "1"` / `--error` step enforced it.
  > **Why root and not `chmod 777`.** Both gate steps filter to `--severity HIGH,CRITICAL`, and Trivy's Dockerfile scanner has no rule for `chmod` at all — it checks instruction-level `RUN`/`COPY` semantics, exactly as Week 13 Task 1 says. `chmod 777` therefore returns **nothing**, at any severity, and the build goes green: a defect that slips the gate is a Task 5 *Red point*, not a Task 4 screenshot. `:latest` is no good either — that is `DS-0001` and Trivy rates it MEDIUM, which this gate filters out. Running as root is `DS-0002` HIGH, so it fails the build for real.

**Red-team PR #1:** **https://github.com/ThuraAung6631503094/week15-devsecops-gate/pull/1** (branch `red-team`, commit `cc2826c`, never merged). **Gate run #3:** https://github.com/ThuraAung6631503094/week15-devsecops-gate/actions/runs/40196136439, result **failure**.

I planted one defect for **each** scanner the README names, all in one PR:
```diff
# requirements.txt
 flask==3.1.3
+urllib3==1.26.4                                  # outdated, vulnerable dependency
# Dockerfile
-USER 65532:65532
+USER root                                        # container runs as root
# config.py (new file)
+INTERNAL_API_TOKEN = "q8Zr1vT3mX9pK2sL7wN4bY6cD0fH5jQe"   # FAKE token, planted for the exercise
```

![Task 4 – PR #1: the security-ci checks fail, with identity stamp](task4-pr.png)

![Task 4 – Trivy job: "Gate — fail on HIGH/CRITICAL (SCA)" fails on urllib3 1.26.4, with identity stamp](task4-trivy-gate.png)

![Task 4 – Gitleaks job: "Gate — fail if any secret found" fails on config.py (generic-api-key), with identity stamp](task4-gitleaks-gate.png)

| Planted defect | Caught by job | Failing gate step | Enforced by | Finding |
|----------------|---------------|-------------------|-------------|---------|
| `urllib3==1.26.4` | **SCA + IaC (Trivy)** | **`Gate — fail on HIGH/CRITICAL (SCA)`** ❌ | `exit-code: "1"` + `severity: HIGH,CRITICAL` | **8 HIGH CVEs**, e.g. CVE-2021-33503 (ReDoS, fixed in 1.26.5) and CVE-2023-43804 (Cookie header not stripped on redirect), up to CVE-2026-97689 |
| `USER root` | **SAST (Semgrep)** (and Trivy config) | **`Gate — fail on Semgrep findings`** ❌ | `semgrep scan … --error` | Semgrep `last-user-is-root`; Trivy config **`DS-0002` HIGH** *"Last USER command in Dockerfile should not be 'root'"* (uploaded in the Trivy config SARIF) |
| Hard-coded token in `config.py` | **Secrets (Gitleaks)** | **`Gate — fail if any secret found`** ❌ | `gitleaks detect … --exit-code 1` | rule **`generic-api-key`**, `config.py:3` |

All three jobs failed, so the PR shows red checks and can't be merged safely. Report-then-gate held up again: every report step and SARIF upload succeeded **before** each gate failed.

**One thing the run reveals (a gap in the gate):** in the Trivy job, the IaC gate (`Gate — fail on HIGH/CRITICAL (IaC)`) was **skipped**. The SCA gate before it failed first, and GitHub skips the rest of a job after a failed step. The root container was still reported in the Trivy config SARIF and was independently blocked by Semgrep's gate. But in a PR that adds an old dependency, the Trivy IaC check would **never actually run**, so a second defect could hide behind the first. Task 5 includes the fix.

### Task 5 — Score Break-the-Build (25 min)
*Goal:* tally Red vs Blue. *Steps:* one Blue point per finding the gate caught, one Red point per finding that slipped through; for any bypass, propose the rule that would have caught it. *Deliverable:* scoreboard + one proposed gate improvement.

**Red-team bypass PR #2:** **https://github.com/ThuraAung6631503094/week15-devsecops-gate/pull/2** (branch `red-bypass`, never merged). It contains only the two tricks README §5 predicts will slip through:
```diff
# Dockerfile
-FROM python:3.12-slim
+FROM python:latest                 # unpinned, mutable base image (DS-0001, MEDIUM)
 ...
+RUN chmod -R 777 /app              # world-writable app directory (CWE-732)
 USER 65532:65532
```

**What happened (two runs):**
1. **Run #4, failure, but not because of the bypass.** Semgrep ✅ and Trivy ✅ (both tricks slipped), but **Gitleaks ❌** found the fake token from **PR #1's `red-team` branch**, even though `red-bypass` never contained it. The workflow checks out with `fetch-depth: 0`, which fetches **every branch**, and `gitleaks detect` scans all of that history. The PR #1 Gitleaks log in `task4-gitleaks-gate.png` says **"4 commits scanned"**: main's 2 + `red-team`'s 1 + `red-bypass`'s 1. I reproduced it locally: with `main` checked out, Gitleaks still reports `config.py` from commit `cc2826c`, which exists only on `red-team`. **Lesson:** once a secret is pushed to *any* branch, it is in the repository. Every full-history scan finds it, and every later PR goes red until it is removed from all refs and **rotated**. Not merging is not enough.
2. **Run #5, success: the bypass works.** After deleting the `red-team` branch (which auto-closed PR #1), I re-triggered PR #2 with an empty commit: https://github.com/ThuraAung6631503094/week15-devsecops-gate/actions/runs/40209073293. **All three jobs ✅**, so the PR with `chmod 777` and `:latest` showed a green build and was ready to merge.

**Reported, but not blocked:** on the PR page, the `github-advanced-security` bot left a review saying it "found potential problems" on the `FROM python:latest` line. That comes from the Trivy SARIF upload, which includes every severity. So the `:latest` problem was **visible** to a reviewer, but the gate still let it through, because the gate only fails on HIGH/CRITICAL. A comment does not stop a merge; only a failing required check does. `chmod 777` can't get a comment at all, because none of the scanners has a rule for it. PR #2 is still **open and not merged**.

![Task 5 – PR #2 (chmod 777 + python:latest): all security-ci checks green, the defects slipped through, with identity stamp](task5-bypass.png)

#### Scoreboard

| # | Defect | PR | Result | Point |
|---|--------|----|--------|:-----:|
| 1 | `urllib3==1.26.4` (8 HIGH CVEs) | #1 | Caught: Trivy SCA gate | 🔵 Blue |
| 2 | `USER root` | #1 | Caught: Semgrep gate (`last-user-is-root`); Trivy config `DS-0002` HIGH reported | 🔵 Blue |
| 3 | Hard-coded token `config.py:3` | #1 | Caught: Gitleaks gate (`generic-api-key`) | 🔵 Blue |
| 4 | `FROM python:latest` | #2 | **Slipped**: `DS-0001` is MEDIUM, the gate filters to HIGH,CRITICAL | 🔴 Red |
| 5 | `RUN chmod -R 777 /app` | #2 | **Slipped**: no Trivy or Semgrep rule for `chmod` at any severity | 🔴 Red |
| **Total** | | | | **Blue 3 – Red 2** |

**Gate weaknesses found while playing:**
- In the Trivy job, **the IaC gate was skipped** in PR #1, because the SCA gate failed first. One defect can hide a second one.
- **The thresholds don't match:** Semgrep's `--error` fails on *any* finding (all 12 alerts in Task 2 were only "Warning"), while Trivy blocks only HIGH/CRITICAL.
- The Semgrep and Gitleaks jobs still use **unpinned `:latest` images** (`semgrep/semgrep:latest`, `zricethezav/gitleaks:latest`), the same issue the gate itself flags in other people's Dockerfiles.

#### Proposed gate improvement: close both bypasses (tested locally)

**1. Catch `chmod 777` with a custom Semgrep rule.** Add it to the Semgrep gate with `--config .semgrep/dockerfile.yml`:
```yaml
rules:
  - id: dockerfile-world-writable-chmod
    languages: [dockerfile]
    severity: ERROR
    message: "chmod 777 makes files world-writable: any process in the container can rewrite the app (CWE-732)"
    pattern-regex: 'chmod\s+(-R\s+)?0?777'
```
**2. Catch `:latest` by raising only the IaC gate to MEDIUM:**
```yaml
      - name: Gate — fail on MEDIUM+ (IaC)
        if: always()                     # also fixes the skip: runs even if the SCA gate failed
        uses: aquasecurity/trivy-action@ed142fd0673e97e23eac54620cfb913e5ce36c25  # v0.36.0
        with:
          scan-type: config
          severity: MEDIUM,HIGH,CRITICAL
          exit-code: "1"
```

| Check (run locally on the PR #2 code) | Before | After |
|---------------------------------------|--------|-------|
| Semgrep + custom rule | pass | **FAIL**: `dockerfile-world-writable-chmod` at `Dockerfile:5` |
| Trivy config `MEDIUM,HIGH,CRITICAL` | pass | **FAIL**: `DS-0001 (MEDIUM): Specify a tag in the 'FROM' statement for image 'python'` |
| Both, on the clean Blue repo | pass | **pass** (no false positives) |

With both changes, PR #2 would have scored **Blue 5 – Red 0**. `if: always()` on the second gate step means every gate reports, even after the first one fails.

---

## Part 4 — Reflection

1. **Mapping.** For three controls you exercised, give: control → A09/A10 (or A02/A03 for a scanner) → CWE → one-line rationale.
2. **Real incident.** Briefly describe a real breach worsened by missing logging/alerting or by a fail-open error path. Which control here would have changed the outcome?
3. **Best mitigation.** Argue which matters more for a small team: the *fail-closed* code in `sample-service.py`, or the *CI gate* in `security-ci.yml` — and why both together beat either alone.

**1. Mapping**

| Control I exercised | OWASP 2025 | CWE | Rationale (from my own run) |
|---------------------|-----------|-----|-----------------------------|
| `except` → **deny** in `/admin` (`sample-service.py` L96–103) | A10 Mishandling of Exceptional Conditions | CWE-636 Not Failing Securely | A forced `RuntimeError` gave **403** (Task 1). The same error in `insecure_service.py` gave **UNLOCKED + the flag** with no token at all (Task 1b). |
| Structured `security` log: `event= outcome= src_ip= reason=`, no token logged | A09 Security Logging & Alerting Failures | CWE-778 Insufficient Logging (and it avoids CWE-532) | Every failure in Task 0 produced one line that can be counted and alerted on. The fail-open service logged **nothing** for the same attack (Task 1b). |
| Trivy SCA gate (`fs`, HIGH/CRITICAL, `exit-code: 1`) | A03 Software Supply Chain Failures | CWE-1395 Dependency on Vulnerable Third-Party Component | It blocked PR #1's `urllib3==1.26.4` (8 HIGH CVEs, e.g. CVE-2023-43804) before merge (Task 4). |
| Gitleaks gate (full history) | A04 Cryptographic Failures (secret handling) | CWE-798 Hard-coded Credentials | It caught the fake token in `config.py:3`, and kept catching it from another branch (Task 5, run #4). |

**2. Real incident: Equifax (2017).** Attackers got in through an unpatched Apache Struts flaw (**CVE-2017-5638**). The patch had been out for two months. They then stayed inside for about **76 days** and took the personal data of roughly **147 million people**. They went unnoticed because the device that inspected outgoing traffic had an **expired TLS certificate**. It had silently stopped inspecting encrypted traffic months earlier, which is a monitoring control that **failed open**. The breach was spotted only when the certificate was renewed and the device suddenly saw the suspicious traffic.
- An **SCA gate** like Trivy flags a vulnerable `struts2-core` version as CRITICAL on every build, so the known-vulnerable component would not ship unnoticed (A03).
- **Fail-closed monitoring with alerting** (A09/A10) would raise an alarm when the inspection device can no longer do its job, instead of passing traffic uninspected. That would turn 76 days of dwell time into hours.

**3. Best mitigation.** For a small team, I'd put the **CI gate first**. It is set up once and then checks **every** change automatically, across three risk areas at once (code, dependencies, secrets), without anyone having to remember. A small team has no security reviewer, and the gate acts like one. But the gate has a hard limit, which I verified. I ran the same Semgrep rule packs on `insecure_service.py` and `secure_service.py`, and both gave **the same single finding** (`avoid_app_run_with_bad_host`). **The gate cannot tell fail-open from fail-closed code.** The bug that leaked the admin flag in Task 1b would pass the gate green, just like the `chmod 777` in Task 5. Only correct **fail-closed code** stops that at runtime, and it also covers failures nobody predicted (a database timeout, a malformed header). Together they cover each other's blind spots:
- The gate catches known-bad patterns, packages and secrets before they ship.
- Fail-closed code plus logging makes the unknown bugs that do ship **deny and alert**, instead of silently granting access.

---

## Grading rubric (100)

| Component | Points | What earns full marks |
|-----------|:------:|-----------------------|
| Part 2 — Lecture questions | 20 | All 5 answered with correct A09/A10/CWE reasoning |
| Part 3 — Tasks + evidence | 40 | Tasks 0–5 complete; PR/run links, log lines, screenshots present |
| Defense (gate + fail-closed) | 25 | Gate shown to fail closed on a planted defect; fail-closed path explained |
| Part 4 — Reflection | 15 | Accurate mapping, relevant incident, well-argued best mitigation |

---

## Evidence & Integrity (required)

- **Identity proof:** every screenshot/diagram must show a terminal running `printf '%s | %s | ' "$(whoami)" '<YOUR-STUDENT-ID>'; date '+%F %T %Z'` **in the
  same image as the evidence**. When the evidence is a browser page, a DevTools panel or a
  rendered response, put that terminal **beside the browser and capture the whole screen** — a
  cropped window carries nothing that identifies you, and the lab's own output is
  byte-identical for the whole cohort *by design*, so the stamp is the only thing that makes
  the shot yours. Generic or borrowed evidence is not accepted.
  *My stamp:* I worked in Windows PowerShell, where `printf` / `date '+%F'` don't exist, so I used the PowerShell equivalent `Write-Output "$(whoami) | Thura Aung | 6631503094 | $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss K')"`. Every browser screenshot (GitHub runs, alerts and PRs) is a full-screen capture with the PowerShell stamp beside the browser. Two notes:
  - `task0-logs.png` has no stamp of its own. It belongs to `task0-requests.png` (stamp **19:27:17 +07:00**): the three security log lines are timestamped **19:27:18**, one second later (Task 0 note). The Task 1b logs come from containers and are in UTC (12:33:27 = 19:33:27 +07:00).
  - The Task 4 and Task 5 stamps (`task4-*.png`, `task5-bypass.png`) were typed without `$(whoami)`, so they show name, ID and time, but not the machine account. The run and PR links in Tasks 2–5 point to my own repo `ThuraAung6631503094/week15-devsecops-gate`, where the results can be checked.
- **Personalized flag (if this lab issues one):** N/A. I ran the lab locally with `docker compose`, with no platform `.env`, so `FLAG_DEVSECOPS` was not set. The fail-open service returned the **default** flag `FLAG{devsecops_fail_open_leaks_admin}` (Task 1b). That is identical for every student, so I'm not submitting it as a personal flag.
  *Flags are unique per student — submitting another student's flag is a violation. How to submit: **learn.zcr.ai/submit** (full guide: `SUBMISSION.md` in the repo root).*
- **Explain in your own words** *(graded on your reasoning, not copied text):*
  1. What did you do, and **why did the vulnerability work**?

     First I attacked the insecure service. I called `/admin` with no token, and it gave me the admin panel and the flag. The code finds the user with `USERS[token]`. When the token is wrong or empty, this line crashes. The code catches the crash, but then it opens the panel instead of saying no. So the error became a back door, and nothing was written to the log.

     Then I made a security gate in GitHub Actions and tried to break it with two pull requests. PR #1 was blocked: the gate caught the old library, the root user and the token. PR #2 passed with a green build, even with `python:latest` and `chmod 777`. The gate only stops HIGH and CRITICAL problems, `:latest` is only MEDIUM, and no rule checks `chmod` at all.
  2. **Why does your fix actually stop it** — and what could still break it?

     In my fixed code, any error now means "no" (403), and it writes one log line. The panel opens in only one place: after the token belongs to an admin. So a crash can't open it anymore. I tested this with 6 attacks in Comprehension B. For the gate, I added a Semgrep rule for `chmod 777` and made the Dockerfile check stop MEDIUM problems too. When I ran them locally, both caught PR #2, and the clean code still passed.

     **What could still break it:**
     - The gate only finds what its rules know. Semgrep gave the same result for the safe code and the fail-open code, so it can't see this kind of logic bug.
     - The Semgrep and Gitleaks images use `:latest`, so they can change without us knowing.
     - Anyone who can edit the workflow file can turn the gate off. Workflow changes need review, and the gate must be a required check.
     - Logs don't help if nobody watches them. We need an alert, for example on many failed logins.

---

## 🤖 Audit the AI (required)

AI is a power tool you must **distrust** — you are graded on your *critique*, not the AI's answer.

1. Ask an AI assistant to exploit **or** fix this week's vulnerability. Paste its full answer.
2. **Find what's wrong or risky** in it — insecure code, a subtly incomplete fix, a hallucinated API/function/CVE, a missed edge case, or wrong reasoning. Quote the exact line(s).
3. Produce the **correct, verified** version yourself and explain in 2–3 sentences why the AI's output was insufficient.

> Disclose your AI use in the Part 1 table. This task counts toward your **Defense + Reflection** score.

**AI used:** Claude (Anthropic), in VS Code. **What I asked:** to fix the lab's security gate so it passes (Task 3), and to plan the Red-team PRs that test it (Tasks 4–5), including what each run should show.

**1. The AI's answer (the parts that matter, quoted exactly):**

> **Plan for the four pushes:**
> | 3 | PR from branch `red-team`: old `urllib3` + `USER root` + fake token | 🔴 Trivy SCA, Trivy IaC, Gitleaks **and** Semgrep all fail | **Task 4**: the failing gate |
> | 4 | PR from branch `red-bypass`: `chmod 777` + `FROM python:latest` | 🟢 **green: both slip through** | **Task 5**: Red points + a gate improvement |

> **After pushing both branches at once:** "I expect the `red-team` PR to go red and `red-bypass` to go **green**, since both of its tricks slip through the gate."

> **Task 3, what the alerts page should show:** "It should show **0 Open** and **12 Closed**."

**2. What was wrong or risky (found by running it, not by reading it):**

| # | Exact line | What actually happened | Why it's wrong |
|---|-----------|------------------------|----------------|
| 1 | "Trivy SCA, Trivy IaC, Gitleaks **and** Semgrep all fail" | In run #3 the **Trivy IaC gate never ran**. It was *skipped*, because the SCA gate earlier in the same job failed first. | It overstates what the gate checked. Steps after a failed step don't run unless they have `if: always()`, so `USER root` was blocked by Semgrep alone. A reader would think there are two independent controls on the Dockerfile when only one actually ran. |
| 2 | "I expect … `red-bypass` to go **green**" (both branches pushed at the same time) | Run #4 on PR #2 went **red**, from **Gitleaks**, on a token that exists only on the *other* branch (`red-team`, commit `cc2826c`). | This is the riskiest mistake: **a hidden coupling between two experiments.** The checkout uses `fetch-depth: 0` (all branches) and `gitleaks detect` scans *all refs*. Pushing both red branches together contaminated the bypass test. Taken at face value, the red ✗ looks like "the gate caught the bypass", which would have scored Blue 5 – Red 0. That is a false sense of security, exactly what this week warns about. |
| 3 | "It should show **0 Open** and **12 Closed**" | **1 Open**, 12 Closed. The open one was Trivy `DS-0026` **LOW** ("No HEALTHCHECK defined"). | Wrong reasoning about the tool: the AI assumed `severity: HIGH,CRITICAL` also filters the SARIF report. trivy-action writes **all** severities to SARIF unless `limit-severities-for-sarif: true` is set. |

**3. Correct, verified version** of the riskiest one (#2): make the PR gate judge **only the PR's own commits**, while the report and the push-to-`main` runs keep scanning the full history:
```yaml
      - name: Gate — fail if any secret found
        env:
          BASE: ${{ github.event.pull_request.base.sha }}   # empty on push / workflow_dispatch
          HEAD: ${{ github.event.pull_request.head.sha }}
        run: |
          RANGE=""
          if [ -n "$BASE" ]; then RANGE="--log-opts=$BASE..$HEAD"; fi   # PR: only this PR's commits
          docker run --rm -v "$PWD:/repo" zricethezav/gitleaks:latest \
            detect -s /repo --exit-code 1 -v $RANGE                      # push to main: all history
```
The SHAs go in through `env:`, not `${{ }}` inside `run:`, so nothing from the event is pasted into the shell script. I verified this locally on 2026-10-26, in a scratch copy of my repo with the `red-team` branch restored at `cc2826c`:

| Gitleaks command | Commits scanned | Result |
|------------------|:---------------:|--------|
| Lab gate as written (all refs), on PR #2's checkout | 4 | **exit 1**: leaks found: 1 (PR #1's token) → false red on PR #2 |
| `--log-opts=main..red-bypass` (PR #2 scoped) | 1 | **exit 0**: no leaks found → the bypass is correctly shown as slipping through |
| `--log-opts=main..red-team` (PR #1 scoped) | 1 | **exit 1**: leaks found: 1 → the planted token is still caught |

**Why the AI's output was insufficient:** it predicted each experiment as if the branches were isolated, but CI checks out the whole repository, so a secret on any branch leaks into every full-history scan. It also described skipped steps as "fail" and assumed a severity filter applied to SARIF. In all three cases the AI described what the gate was *meant* to do, not what it *actually* did, and only running it and reading the job steps showed the difference. The PR-scoped gate fixes the test, but it does **not** make the leaked token safe. It is still in the repo and still reported by the full-history SARIF, so it must be removed from every ref and rotated.

---

## 🧠 Comprehension & Prompt (required)

**A. Explain in Plain English (EiPE).** In 2–3 sentences, in your own words, describe what this week's vulnerable code/endpoint actually *does* and *why it is exploitable* — explain the mechanism, don't dump jargon.

The `/admin` page checks your token by looking it up in a list of users. If you send no token or a wrong one, the lookup crashes. The code catches every crash, but then it shows the admin panel and the secret instead of blocking you. So an attacker doesn't need a password. They only need to make the check fail, and because nothing is logged, nobody notices.

**B. Prompt Problem.** Write a **single prompt** that makes an AI produce a *correct, secure* fix for one finding. Run it: does the exploit now fail? If not, refine the prompt and try again. Submit the **final prompt + the verified result**.
*Graded on the prompt's precision and your verification — this trains problem decomposition and AI literacy (Denny et al. 2024).*

**Finding fixed:** the fail-open `/admin` in `insecure_service.py` (A10 / CWE-636), together with its silent error path (A09).

**Final prompt:**
> You are fixing ONE function, `admin()` in this Flask file (`insecure_service.py`), which **fails open** (OWASP A10, CWE-636): `user = USERS[token]` raises `KeyError` for a missing or unknown `Authorization` token, and the `except Exception:` block returns `jsonify(panel="UNLOCKED", secret=SECRET)`. It also writes no security log (A09). [full file pasted]
> Produce a drop-in replacement where: **(1)** the lookup uses `USERS.get(token)`; a missing/unknown token → **401**, a known non-admin → **403**; **(2)** `return jsonify(panel="UNLOCKED", secret=SECRET)` appears **exactly once**, on the path where a valid token maps to a user in `ADMINS`; **(3)** the `except` block **denies with 403** and logs only `type(exc).__name__`, never the exception message (CWE-209); **(4)** every decision writes ONE line to a logger named `security` in the form `event=<authn_failure|authz_failure|authz_success|authz_error> outcome=<allow|deny> src_ip=<ip> ...`, where `src_ip` comes from `request.remote_addr` only, **never `X-Forwarded-For`** (CWE-348), the token is **never logged** (CWE-532), and no attacker-supplied text goes into the log line (CWE-117).
> Keep `SECRET`, `USERS`, `ADMINS` and the route unchanged; bind to `127.0.0.1`, `debug=False`. Then give a test using Flask's `test_client` that sends: no header, a bogus token, `bob-token`, `alice-token`, a bogus token with `X-Forwarded-For: 10.9.9.9 event=authz_success outcome=allow`, and a forced exception in the lookup (replace `USERS` with an object whose lookup raises `RuntimeError` with a password in the message). Assert that the secret is returned **only for alice**, and print the security log for each case.

**Why the prompt is written this way:** each rule closes a hole I saw earlier in this lab:
- **Rule (2), "exactly once":** the lab bug is a *second* copy of the success response in the error handler.
- **Rule (3):** Task 1 showed that the safe pattern logs the error type, not the message (the message could carry a DB password).
- **Rule (4), "never X-Forwarded-For":** in Task 1, I showed that the client-controlled XFF header can inject fake `event=authz_success` fields into `sample-service.py`'s log.
- **The XFF test and forced-exception test** turn "the exploit now fails" into something the test can check automatically.

**Result** (produced with Claude, saved as `insecure_fixed.py` in a scratch folder). The lab file was left unchanged. The core of the fix:
```python
    try:
        token = request.headers.get("Authorization", "")
        user = USERS.get(token)                       # no KeyError: unknown -> None
        if user is None:
            _audit("authn_failure", "deny", reason="bad_token")
            return jsonify(error="unauthorized"), 401
        if user not in ADMINS:
            _audit("authz_failure", "deny", subject=user, reason="not_admin")
            return jsonify(error="forbidden"), 403
        _audit("authz_success", "allow", subject=user)
        return jsonify(panel="UNLOCKED", secret=SECRET)  # the ONLY path that returns SECRET
    except Exception as exc:
        # FAIL CLOSED: any error denies. Log the class name only (CWE-209).
        _audit("authz_error", "deny", error=type(exc).__name__)
        return jsonify(error="forbidden"), 403
```
`_audit()` writes `event=… outcome=… src_ip=<request.remote_addr> …` to the `security` logger. Its only inputs are server-side values: constant reason codes, usernames from `USERS`, and the exception class name.

**Verification:** I ran the same 6 attacks against the lab's `insecure_service.py` (imported read-only) and against the fix on 2026-10-26:

| Attack | Lab `insecure_service.py` | Fixed |
|--------|---------------------------|-------|
| No `Authorization` header | **200, flag returned**, no log | **401**, `event=authn_failure outcome=deny src_ip=127.0.0.1 reason=bad_token` |
| Bogus token `nope` | **200, flag returned**, no log | **401**, `event=authn_failure … reason=bad_token` |
| `bob-token` (not admin) | 403, no log | **403**, `event=authz_failure … subject=bob reason=not_admin` |
| `alice-token` (admin, legitimate) | 200, flag returned, no log | **200, flag returned**, `event=authz_success outcome=allow … subject=alice` |
| Bogus token + spoofed `X-Forwarded-For: 10.9.9.9 event=authz_success outcome=allow` | **200, flag returned**, no log | **401**, logged `src_ip=127.0.0.1`: the fake fields never reach the log |
| Forced `RuntimeError("db timeout: postgres://admin:hunter2@…")` | **200, flag returned**, no log | **403**, `event=authz_error outcome=deny src_ip=127.0.0.1 error=RuntimeError`: no password in the log |

**Did the exploit fail?** Yes. The Task 1b attack (no token / bogus token) and the forced crash now **deny** and leave a log line that can be alerted on. Only alice still gets the panel. The first result met every rule, so the prompt didn't need refining.
