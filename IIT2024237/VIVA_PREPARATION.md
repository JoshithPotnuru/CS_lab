# IIIT Allahabad | Cyber Security (IT-30001)
## Viva Voce Preparation Guide — Stored XSS & Context-Aware Encoding
### Instructor: Dr. Soumyadev Maity | Autumn Semester 2026

This guide prepares you to answer every anticipated conceptual and code-level question during the individual viva examination.

---

### Q1: What is Cross-Site Scripting (XSS), and how does Variant 1 (Stored XSS) fundamentally differ from Variant 2 (Reflected XSS)?
**Answer:**  
- **Cross-Site Scripting (XSS)** is an injection vulnerability where an attacker injects malicious client-side scripts into web pages viewed by other users. The victim's browser executes the script under the trust and permissions of the vulnerable application's domain.
- **Stored XSS (Variant 1):** The malicious input is persistently saved in the application's backend storage (database, file system, or comments log). Whenever any user accesses the affected page, the server retrieves and serves the stored script, attacking the victim automatically without requiring any special user action other than browsing.
- **Reflected XSS (Variant 2):** The malicious input is non-persistent; it is passed in an immediate request (such as a search query parameter in a URL) and reflected back into the immediate response. It requires social engineering, such as convincing the victim to click a specially crafted malicious link.

---

### Q2: Why does the browser execute a malicious comment instead of just showing it as plain text?
**Answer:**  
Web browsers use an **HTML Parser** that reads incoming characters as a continuous stream of tokens.  
When an application directly concatenates untrusted input (e.g., `<div>${content}</div>`), the parser encounters the character `<`. In the HTML state machine, `<` signifies a transition from **Data State** to **Tag Open State**. When followed by `script`, the parser switches to the **Script Data State** and passes the inner text directly to the browser's JavaScript V8/SpiderMonkey engine for execution.  
The browser has no semantic awareness of the developer's intent; it strictly follows the HTML specification.

---

### Q3: What is "Context-Aware Output Encoding" and why is generic HTML entity encoding not enough?
**Answer:**  
Browsers parse data differently depending on the syntactic **context** in which data appears. A single encoding method cannot protect all contexts:
1. **HTML Body Context (`<div>...</div>`):** Requires HTML entity encoding (`<` to `&lt;`, `>` to `&gt;`, `&` to `&amp;`).
2. **HTML Attribute Context (`<input value="...">`):** If an attacker inputs `x" onfocus="alert(1)`, they break out of quotes. Encoding must handle quotation marks (`"` to `&quot;`, `'` to `&#x27;`) and non-alphanumeric characters.
3. **JavaScript Context (`<script>let user = "...";</script>`):** Inside a `<script>` block, HTML entity encoding like `&lt;` is **useless** because the browser does not parse HTML entities inside script blocks! An attacker could simply write `"; alert(1); //`. This context requires **Unicode escaping** (`\u0022`, `\u0027`) or safe JSON serialization.
4. **URL Context (`<a href="...">`):** Standard HTML encoding does not prevent pseudo-protocols like `javascript:alert(1)`. This requires URL protocol validation (allowing only `http:` / `https:`) followed by URL encoding (`encodeURI`).

---

### Q4: Why shouldn't we rely on input blacklisting (e.g., stripping `<script>` tags)?
**Answer:**  
Input blacklisting (filtering out words like `<script>`) is fundamentally flawed and easily bypassed:
1. **Case variations:** `<sCrIpt>alert(1)</sCrIpT>`
2. **Nested tags:** `<scr<script>ipt>alert(1)</script>` (if the filter only does a single-pass removal).
3. **Alternative HTML vectors:** Over 100+ HTML tags execute JavaScript without `<script>`:
   - `<img src=x onerror=alert(1)>`
   - `<svg onload=alert(1)>`
   - `<body onload=alert(1)>`
   - `<iframe src="javascript:alert(1)">`
   - `<details open ontoggle=alert(1)>`
Output encoding is vastly superior because it does not attempt to predict malicious syntax; it ensures that **all** user data is treated as literal character data.

---

### Q5: How does the browser handle `&lt;script&gt;` differently from `<script>`?
**Answer:**  
When the HTML parser encounters `&lt;`, it recognizes an HTML character reference (entity). Instead of transitioning to the **Tag Open State**, the parser remains in the **Character Data State**, resolves the entity to the literal character `<`, and paints it onto the screen as text. No `<script>` DOM element is ever constructed, completely neutralizing the attack.

---

### Q6: What is Content Security Policy (CSP) and how does it defend against XSS?
**Answer:**  
Content Security Policy (CSP) is an HTTP response header (e.g., `Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-RANDOM_HEX'`) that enforces defense-in-depth:
- It restricts which origins can supply executable scripts.
- It disables inline scripts (`<script>...</script>`) and inline event handlers (`onload`, `onerror`) unless they carry a cryptographically secure, single-use `nonce` generated by the server for that specific HTTP response.
- It blocks dynamic code evaluation (`eval()`, `new Function()`).  
Even if an attacker successfully injects an unencoded `<script>` tag into the page, the browser's CSP engine refuses to execute it.

---

### Q7: Does the `HttpOnly` cookie flag prevent XSS?
**Answer:**  
**No, `HttpOnly` does NOT prevent XSS.**  
`HttpOnly` only prevents client-side scripts from reading the cookie value via `document.cookie`.  
Even with `HttpOnly` enabled, an XSS payload can still:
- Deface the webpage or phish user credentials by injecting a fake login form.
- Perform actions on behalf of the victim using the browser's ambient credentials (session cookies) via `fetch()` or `XMLHttpRequest`.
- Read sensitive data displayed on the page DOM.  
`HttpOnly` is a valuable mitigation against session token exfiltration, but output encoding or CSP is required to prevent the XSS execution itself.

---

### Q8: What are "Safe DOM Sinks" versus "Unsafe DOM Sinks"?
**Answer:**  
In client-side JavaScript:
- **Unsafe Sinks:** `element.innerHTML = data`, `element.outerHTML = data`, `document.write(data)`, and `eval(data)` pass untrusted strings directly into the browser's HTML or JavaScript parser, creating DOM-based or Stored XSS.
- **Safe Sinks:** `element.textContent = data` and `element.innerText = data` assign data directly to the DOM node's text content, completely bypassing the HTML parser and guaranteeing that metacharacters are treated as literal text.

---

### Q9: How do modern frameworks (React, Angular, Vue) mitigate XSS by default?
**Answer:**  
Modern frameworks employ **Framework Auto-Escaping**:
- In React JSX: `{comment.content}` is automatically converted into text nodes using safe DOM APIs (analogous to `textContent`).
- In Angular: Interpolation `{{ comment.content }}` automatically treats values as untrusted strings and encodes them based on context.
To insert raw unescaped HTML in React, a developer must explicitly use the dangerously named property `dangerouslySetInnerHTML={{ __html: data }}`, which highlights the security risk during code review.

---

### Q10: If a question is asked about your implementation during viva, where is the code?
**Answer:**
- **Vulnerable Code Path:** `views.js`, lines 20–35 (raw template literal `${c.content}`).
- **Implemented Mitigation:** `utils/encoder.js` (methods `encodeForHTML()`, `encodeForHTMLAttribute()`, `encodeForURL()`).
- **Applied Mitigation:** `views.js`, lines 45–65 (calling `encoder.encodeForHTML(c.content)`).
- **Persistent Storage:** `db.js` saving to `comments.json`.
- **Mode Toggle Controller:** `server.js` (`?mode=vulnerable` vs `?mode=mitigated`).
