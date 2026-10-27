# Stored XSS Video Demonstration Script
## Cyber Security (IT-30001) | Autumn Semester 2026 | IIIT Allahabad
### Instructor: Dr. Soumyadev Maity

- **Presenter:** [Your Name] (Roll No: [Your Roll Number])
- **Vulnerability Category:** Cross-Site Scripting (XSS)
- **Variant:** Variant 1: Stored XSS
- **Target Video Duration:** ~2 minutes 30 seconds

---

## Preparation Before Recording
1. Start the application:
   ```bash
   cd Ass4
   npm start
   ```
2. Open your browser at: `http://localhost:3000/?mode=vulnerable`
3. Have your code editor (VS Code) open with `views.js` and `utils/encoder.js`.

---

## Timed Scene-by-Scene Script

### Scene 1: Introduction (0:00 – 0:25)
- **On Screen:** Browser displaying `http://localhost:3000/?mode=vulnerable` showing the clean "Community Hub" discussion portal with "Vulnerable Mode" active.
- **Spoken Voiceover:**
  > *"Hello everyone and respected Dr. Soumyadev Maity sir. My name is [Your Name], roll number [Your Roll Number].*  
  > *For our group assignment in Web Server Security, my individual variant is **Cross-Site Scripting (XSS) — Variant 1: Stored XSS**.*  
  > *Here we have a discussion board application where users can post comments. I will demonstrate how unencoded comment storage leads to persistent XSS, explain the root cause, and then show our defense using **Context-Aware Output Encoding**."*

---

### Scene 2: Vulnerable Implementation & Exploit (0:25 – 1:10)
- **On Screen:**
  1. Briefly show `views.js` in VS Code (lines 18–35), pointing out the unencoded `${c.content}` interpolation.
  2. Switch to the browser at `http://localhost:3000/?mode=vulnerable`.
  3. Fill out the comment form:
     - **Name:** `Attacker`
    - **Comment:** `<script>alert('Stored XSS Executed! Session: ' + document.cookie)</script>`
  4. Click **"Post Comment"**.
  5. The alert popup appears immediately showing the active cookie.
  6. Refresh the page to show that the alert pops up again automatically.
- **Spoken Voiceover:**
  > *"First, let's look at the vulnerable code path in `views.js`. The server stores incoming comments in our database. When serving the discussions feed, it directly concatenates the raw user comment into the HTML document using template string interpolation without escaping.*  
  > *Now, in Vulnerable Mode, I will submit an exploit payload containing a script tag that accesses `document.cookie`.*  
  > *[Clicks Post Comment]*  
  > *As soon as the page loads, the stored comment executes immediately, popping up this alert box and exposing the session cookie.*  
  > *Because this is Stored XSS, the payload is permanently stored in the database. Every time I refresh the page, or whenever any other user visits this forum, the script executes automatically."*

---

### Scene 3: Root Cause Explanation (1:10 – 1:40)
- **On Screen:** Right-click the comment card in the browser, click **"Inspect"** in Chrome DevTools to show `<script>` residing as an active DOM node inside `<div class="comment-body">`.
- **Spoken Voiceover:**
  > *"The root cause of this vulnerability is a lack of boundary separation between untrusted data and code markup.*  
  > *The server outputs raw user input directly into the HTML response stream. Because the browser's HTML parser cannot differentiate between developer-intended markup and user-supplied data, the `<` character causes the parser to transition from data parsing state to tag parsing state. The injected JavaScript is then executed with full privileges under the application's domain."*

---

### Scene 4: Implemented Mitigation — Context-Aware Output Encoding (1:40 – 2:20)
- **On Screen:**
  1. Click the top toggle button: **"🛡️ Mitigated (Encoded)"** (`/?mode=mitigated`).
  2. The page reloads. Notice the previously stored payload is now safely displayed on the screen as plain harmless text: `<script>alert('Stored XSS Executed! Session: ' + document.cookie)</script>`.
  3. Submit another test payload: `<img src=x onerror="alert('XSS')">`.
  4. Show that no popup fires!
  5. Inspect the element in Chrome DevTools to show that the browser received `&lt;script&gt;` instead of `<script>`.
- **Spoken Voiceover:**
  > *"Now, let's examine our implemented mitigation: **Context-Aware Output Encoding**, implemented in `utils/encoder.js`.*  
  > *I will switch the server to Mitigated Mode using the toggle in the header.*  
  > *Notice that without altering the database, the exact same payload that previously triggered the popup is now rendered safely on screen as plain text.*  
  > *Even if I submit a new payload like an `<img onerror>` vector, no alert fires.*  
  > *In Chrome DevTools, we can see that our encoder converts `<` into `&lt;`, `>` into `&gt;`, and quotes into `&#x27;`. Because the browser parser encounters character entities rather than raw tags, it remains in the character data state, completely blocking execution."*

---

### Scene 5: Other Mitigations & Conclusion (2:20 – 2:45)
- **On Screen:** Face camera or keep the clean mitigated forum on screen.
- **Spoken Voiceover:**
  > *"Beyond output encoding, the lecture slides discuss several other key mitigations:*  
  > *1. Framework Auto-Escaping, such as React JSX or Angular templates which encode by default.*  
  > *2. HTML Sanitisers like DOMPurify for rich text.*  
  > *3. Content Security Policy (CSP) to block inline scripts.*  
  > *4. HttpOnly cookies to prevent cookie theft via `document.cookie`.*  
  > *5. Safe DOM Sinks like `textContent` instead of `innerHTML`.*  
  > *This concludes my demonstration for Stored XSS. Thank you."*
