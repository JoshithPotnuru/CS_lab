# Web Server Security: Stored XSS Exploitation and Mitigation Lab
## Cyber Security (IT-30001) | Autumn Semester 2026 | IIIT Allahabad

**Instructor:** Dr. Soumyadev Maity  
**Evaluation:** Group Repository, 2–3 Minute Video Demonstration, and Individual Viva Voce  

---

## Table 3: Ownership Declaration

| Member Name | Roll Number | Vulnerability Category | Variant Implemented | Implemented Mitigation |
| :--- | :--- | :--- | :--- | :--- |
| **[Your Name]** | **[Your Roll Number]** | **Cross-Site Scripting (XSS)** | **Variant 1: Stored XSS** | **Context-Aware Output Encoding** |
| [Member 2] | [Roll 2] | SQL Injection | Variant 1 / 2 | Parameterised Queries |
| [Member 3] | [Roll 3] | OS Command Injection | Variant 1 / 2 | Parameterised Execution |
| [Member 4] | [Roll 4] | CSRF | Variant 1 / 2 | Anti-CSRF Synchronizer Tokens |

---

## 1. Quick Start Guide

### Prerequisites
- [Node.js](https://nodejs.org/) (v18, v20, or v22)
- Any modern web browser (Google Chrome, Firefox, Microsoft Edge)

### Installation & Launch
```bash
# 1. Navigate to directory
cd Ass4

# 2. Install dependencies (express, cookie-parser)
npm install

# 3. Start the application
npm start
```

Open your browser at: **`http://localhost:3000`**

### Modes & Navigation
- **Vulnerable Mode (Flaw Active):** `http://localhost:3000/?mode=vulnerable`
- **Mitigated Mode (Defense Active):** `http://localhost:3000/?mode=mitigated`
- **Reset Comments:** Click **"Reset Comments"** in the UI or visit `http://localhost:3000/reset`

---

## 2. Table 2 Requirements Breakdown

### (a) Vulnerable Implementation
The vulnerability is isolated in [`views.js`](file:///c:/Users/joshi/cyber_security/Ass4/views.js#L15-L35):

```javascript
// Vulnerable Code Path: views.js (Lines 18–35)
// Raw user comment from database is concatenated into HTML without encoding
return `
<article class="comment-card vulnerable-card" id="comment-${c.id}">
    <div class="comment-meta">
        <span class="comment-author">${escapeOnlyAuthor(c.author)}</span>
        <span class="comment-time">${c.timestamp}</span>
    </div>
    <div class="comment-body">
        ${c.content}  <!-- FLAW: Unescaped interpolation into HTML body context -->
    </div>
    ${c.website ? `<a href="${c.website}">🔗 ${c.website}</a>` : ''} <!-- URL context flaw -->
</article>`;
```
**Code Path Explanation:** User comments submitted via `POST /comment` are saved to persistent backend storage ([`comments.json`](file:///c:/Users/joshi/cyber_security/Ass4/comments.json)) and rendered directly into the HTML document stream without encoding or sanitization.

---

### (b) Working Exploit
An attacker submits an executable JavaScript payload into the comment field. It is saved in `comments.json`. When any user opens the page, the payload executes automatically in their browser.

#### Working Payloads:
1. **Standard Inline Script:**
   ```html
   <script>alert('Stored XSS Executed! Session: ' + document.cookie)</script>
   ```
2. **Event Handler (Bypasses naive `<script>` tag filters):**
   ```html
   <img src=x onerror="alert('Stored XSS via IMG onerror!')" />
   ```

#### Reproduction Steps (for Video & Viva):
1. Switch to **Vulnerable Mode** (`/?mode=vulnerable`).
2. In the **"Leave a Comment"** form, enter:
   - **Your Name:** `Tester`
   - **Comment:** `<script>alert('Stored XSS: ' + document.cookie)</script>`
3. Click **"Post Comment"**.
4. The page reloads and an alert box immediately pops up showing the active session cookie (`sess_...`).
5. Refreshing the page triggers the alert again, confirming that the payload is **stored persistently**.

---

### (c) Root Cause Analysis
> **Root Cause:** The application fails to maintain strict syntactic separation between untrusted user data and executable markup. Untrusted strings are stored in persistent storage and interpolated directly into the HTML document stream. Because the browser's HTML parser cannot differentiate between developer-intended markup and user-supplied data, metacharacters such as `<`, `>`, `"`, `'`, and `&` cause the parser's state machine to transition from **Character Data State** to **Tag/Script Parsing State**, executing attacker-supplied JavaScript within the victim's session context.

---

### (d) Mitigation Implemented: Context-Aware Output Encoding
The vulnerability is resolved by applying **Context-Aware Output Encoding** in [`utils/encoder.js`](file:///c:/Users/joshi/cyber_security/Ass4/utils/encoder.js) before rendering data:

#### 1. HTML Body Context (`<div>...</div>`):
Converts characters that alter HTML document structure into standard character entities:

| Raw Character | Encoded Entity | Security Purpose |
| :---: | :---: | :--- |
| `&` | `&amp;` | Prevents entity confusion |
| `<` | `&lt;` | Prevents transition to Tag Open State (`<script>`, `<img>`) |
| `>` | `&gt;` | Prevents premature tag closure |
| `"` | `&quot;` | Prevents attribute breakout |
| `'` | `&#x27;` | Universal XML/HTML single-quote breakout defense |
| `/` | `&#x2F;` | Prevents closing tag breakout (`</script>`) |

```javascript
// Mitigated Code Path: views.js (Lines 40–58)
const safeAuthor = encoder.encodeForHTML(c.author);
const safeContent = encoder.encodeForHTML(c.content);
const safeWebsite = encoder.encodeForURL(c.website);

return `
<article class="comment-card safe-card">
    <div class="comment-body">
        ${safeContent} <!-- Rendered safely as literal character entities -->
    </div>
</article>`;
```

#### Verification:
1. Switch to **Mitigated Mode** (`/?mode=mitigated`).
2. The exact same stored payload `<script>alert(...)</script>` is now received by the browser as `&lt;script&gt;alert(...)&lt;&#x2F;script&gt;`.
3. The browser remains in **Character Data** state, rendering the payload as plain harmless text on screen.
4. **No script executes, and no alert popup appears.**

---

### (e) Other Mitigations from Slides (Theory)

1. **Framework Auto-Escaping:**  
   Modern templating engines and UI frameworks (e.g., React JSX, Angular, Vue, Jinja2, EJS with `<%= %>`) automatically apply context-aware output encoding by default. They treat template variables as text nodes rather than HTML markup, eliminating manual escaping mistakes unless explicitly bypassed using unsafe properties (e.g., `dangerouslySetInnerHTML`).

2. **HTML Sanitiser for Rich Text:**  
   When applications intentionally allow users to submit formatted HTML (e.g., `<b>`, `<i>`, `<a>` in rich text/WYSIWYG editors), simple output encoding destroys legitimate formatting. A robust HTML sanitiser (such as **DOMPurify** on the client or **bleach / sanitize-html** on the server) parses markup against a strict allow-list, stripping dangerous tags (`<script>`, `<object>`, `<iframe>`) and active event handlers (`onload`, `onerror`).

3. **Content Security Policy (CSP):**  
   CSP is an HTTP response header (e.g., `Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-rAnd0m'`) that instructs the browser to restrict script execution sources. It effectively disables inline scripts, `eval()`, and unapproved external scripts, serving as an essential defense-in-depth barrier if an injection flaw exists.

4. **HttpOnly Cookie Flag:**  
   Setting the `HttpOnly` flag on sensitive cookies (`Set-Cookie: sessionId=...; Secure; HttpOnly; SameSite=Lax`) instructs the browser to block client-side JavaScript access via `document.cookie`. While this does not prevent XSS itself, it eliminates the primary post-exploitation objective: direct session hijacking and cookie theft.

5. **Safe DOM Sinks:**  
   When manipulating the DOM client-side with JavaScript, developers must use safe APIs that treat data strictly as text, such as `element.textContent = data` or `element.innerText = data`. Unsafe DOM sinks like `element.innerHTML = data`, `document.write()`, and `eval()` directly invoke the browser's HTML/JS parsing engine on untrusted strings.
