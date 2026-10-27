
# CSRF - Cross-Site Request Forgery Lab

---

## 📂 Project Structure

```text
IIT2024260-CSRF/
├── package.json          # Project scripts and dependencies
├── server.js             # Banking application (port 3000)
├── README.md             # Project documentation
├── .gitignore            # Excluded files and folders
└── attacker/
    ├── server.js         # Attacker server (port 3001)
    └── csrf-get.html     # Fake prize page demonstrating the attack
```

---

## ⚙️ Setup and Execution

### 1. Install Dependencies

Open a terminal in the project directory and run:

```bash
npm install
```

### 2. Start the Application in Vulnerable Mode

Open two separate terminals.

**Terminal 1 – Banking Application**

```bash
npm start
```

Access the application at [http://localhost:3000](http://localhost:3000).

**Terminal 2 – Attacker Website**

```bash
npm run attacker
```

Open the attack page at [http://localhost:3001/csrf-get.html](http://localhost:3001/csrf-get.html).

### 3. Start the Application in Secure Mode

Stop the victim server and run:

```bash
npm run start:secure
```

The application will restart on port 3000 with Secure Mode enabled. Keep the attacker server running on port 3001.

---

## Demonstration Procedure

### A. Testing the Vulnerability

1. Start both servers in Vulnerable Mode.
2. Visit [http://localhost:3000/login](http://localhost:3000/login) and sign in using **koushik / Koushik@Secure2026**.
3. Check the starting balances: Koushik has **₹1000**, while the attacker has **₹0**.
4. Open [http://localhost:3001/](http://localhost:3001/) in another tab without logging out.
5. On the fake iPhone giveaway page, click **"Click Here to Win an iPhone"**.
6. The page triggers a hidden image request to `GET /transfer?to=attacker&amount=500`.
7. Return to the banking dashboard and refresh it. The balances should now be **Koushik: ₹500** and **Attacker: ₹500**.
8. Use **"Reset Balances (₹1000 / ₹0)"** to restore the initial state.

### B. Verifying the Security Fix

1. Restart the victim application using `npm run start:secure`.
2. Sign in again with **koushik / Koushik@Secure2026**.
3. Visit the attacker page and repeat the GET-based attack.
4. The server rejects the request with **HTTP 405 Method Not Allowed**.
5. Refresh the dashboard. The balances should remain **₹1000 / ₹0**.
6. Test a legitimate transaction through the banking form by entering `attacker` and `500`.
7. The transfer succeeds because the legitimate form supplies a valid `_csrf` token.

---

## 🔎 Vulnerability Explanation

The issue arises because the application allows a GET request to modify account balances. An external webpage can trigger this request through a hidden image element. If the victim's authenticated session is accepted, the server may execute the transfer without the user's intentional approval.

---

## 🔐 Security Measures

| Protection | Purpose |
|---|---|
| **CSRF Synchronizer Token** | Generates a random token using Node.js `crypto` and validates it on legitimate POST requests. |
| **HTTP Method Restriction** | Blocks state-changing GET requests with HTTP 405 in Secure Mode. |
| **SameSite=Strict** | Restricts the browser from sending the session cookie with cross-site requests. |
| **HttpOnly** | Prevents JavaScript from directly accessing the session cookie. |

### Additional Defenses (Theory)

- **SameSite Cookie Policies:** `Lax` and `Strict` restrict cookie transmission in different cross-site scenarios.
- **Double-Submit Cookie:** Checks a matching CSRF value supplied through a cookie and a request parameter or header.
- **Additional Authentication:** Password confirmation or OTP verification can provide another layer of protection for sensitive transactions.

---

## Student Details

| Student Name | Roll Number | Assignment | Implemented Variant |
|---|---|---|---|
| Ganapuram Mani Koushik | IIT2024260 | CSRF | GET-based forged action |

- **Group Number**: 24

---
