# Web Server Security Assignment — SQL Injection (Variant 1: Authentication Bypass)

**Course:** Cyber Security (IT-30001), Autumn 2026, IIIT Allahabad
**Member:** Shiva
**Category:** SQL Injection
**Variant:** Variant 1 — Authentication bypass

## What this is

A minimal Flask + SQLite login app with two routes:

- `/vulnerable` — login built by concatenating user input directly into a SQL string (the flaw).
- `/secure` — the same login rewritten using a parameterized query (the mitigation).

Both routes share the same `users` table so the before/after comparison is apples-to-apples.

## How to run

```bash
cd vulnerable_app
python3 init_db.py      # creates users.db with seed users (admin/alice/bob)
python3 app.py           # starts server at http://127.0.0.1:5000
```

Only run this on localhost, for the assignment. Never expose it to the network.

## Demo login (works on both `/secure` and `/vulnerable`)

| Username | Password | Role |
|---|---|---|
| `shiva` | `Shiva@2026` | student |

Use the Secure / Vulnerable switch at the top of each page to flip between implementations. Payload chips on the page auto-fill the attack inputs.

## (a) Vulnerable implementation

File: `vulnerable_app/app.py`, route `vulnerable_login()` (`/vulnerable`).

```python
query = (
    "SELECT * FROM users WHERE username = '"
    + username
    + "' AND password = '"
    + password
    + "'"
)
cur = db.execute(query)
```

## (b) Working exploit

Login form at `/vulnerable`:

- **Username:** `admin' --`
- **Password:** (anything, e.g. `x`)

Resulting query:

```sql
SELECT * FROM users WHERE username = 'admin' --' AND password = 'x'
```

`--` starts a SQL comment, so everything after it (the password check) is discarded. The query becomes "find the user named admin," and the login succeeds with no valid password. Verified with curl:

```bash
curl -X POST http://127.0.0.1:5000/vulnerable \
  --data-urlencode "username=admin' --" \
  --data-urlencode "password=anything"
# -> "Logged in as 'admin' (role: admin)"
```

The page also displays the exact query string executed, for the video demo.

## (c) Root cause

User-supplied input (`username`, `password`) is concatenated directly into the SQL command text instead of being passed as data. This lets an attacker inject SQL metacharacters (`'`, `--`) that change the structure/logic of the query rather than just supplying a value for it.

## (d) Mitigation implemented

File: `vulnerable_app/app.py`, route `secure_login()` (`/secure`), using a parameterized query:

```python
query = "SELECT * FROM users WHERE username = ? AND password = ?"
cur = db.execute(query, (username, password))
```

The driver sends the SQL text and the values separately, so `admin' --` is treated as a literal username string to search for (which doesn't exist) rather than as SQL syntax. Same payload, now blocked:

```bash
curl -X POST http://127.0.0.1:5000/secure \
  --data-urlencode "username=admin' --" \
  --data-urlencode "password=anything"
# -> "Invalid username or password."
```

## (e) Other mitigations (theory, for viva)

In addition to parameterized queries (implemented above), the lecture material covers:

- **Input validation with allow-lists** — restrict input to an expected character set/format (e.g. usernames limited to alphanumerics) so SQL metacharacters like `'` and `--` are rejected before ever reaching the query. Useful as defense-in-depth but not sufficient alone, since legitimate data can still contain special characters in other contexts.
- **Least-privilege database accounts** — the application's DB user should only have the minimum permissions it needs (e.g. SELECT on specific tables, no DROP/ALTER). This limits the damage an injected query can do even if one slips through.
- **Safe/generic error handling** — avoid returning raw database error messages to the client (e.g. SQL syntax errors), since these leak schema information that helps an attacker refine further injection attempts.

Parameterized queries are preferred as the primary fix because they eliminate the vulnerability class structurally — the query's grammar is fixed before user input is ever combined with it — rather than relying on filtering, which can be bypassed by encoding tricks or edge cases.

## Ownership declaration

| Member | Roll number | Category | Variant |
|---|---|---|---|
| Shiva | _(fill in)_ | SQL Injection | Variant 1 — Authentication bypass |

_(Add other group members' rows here as applicable.)_

## Next steps for you

1. Push this folder to a public GitHub repo for your group.
2. Record your 2–3 minute segment: show the `/vulnerable` route, type the payload, show the bypassed login; then show `/secure`, same payload, show it blocked.
3. Fill in your roll number above and merge with your group's variants for the other three categories.
4. Review the root-cause and alternative-mitigations sections above — the viva is individual, so be ready to explain them in your own words.
