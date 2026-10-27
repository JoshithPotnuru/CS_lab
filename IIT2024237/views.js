/**
 * Views & HTML Rendering Engine
 * 
 * Provides a clean, modern, and realistic discussion portal UI.
 * Handles both:
 * 1. Vulnerable Path: Raw string concatenation (Stored XSS)
 * 2. Mitigated Path: Context-Aware Output Encoding (Secure)
 */

const encoder = require('./utils/encoder');

function renderPage({ mode, comments, alertMessage }) {
    const isMitigated = (mode === 'mitigated');

    // Build comments list depending on active mode
    const commentsHtml = comments.map(c => {
        if (!isMitigated) {
            // =========================================================================
            // VULNERABLE CODE PATH:
            // Untrusted user input from database is concatenated into HTML without encoding.
            // When c.content contains <script>alert(1)</script>, it executes in the browser.
            // =========================================================================
            const renderedHtmlSnippet = `<div class="comment-body">\n    ${c.content}\n</div>`;

            return `
            <article class="comment-card vulnerable-card" id="comment-${c.id}">
                <div class="comment-meta">
                    <span class="comment-author">${escapeOnlyAuthor(c.author)}</span>
                    <span class="comment-time">${c.timestamp}</span>
                    <span class="badge badge-vuln">Raw HTML</span>
                </div>
                <div class="comment-body">
                    ${c.content}
                </div>
                ${c.website ? `
                <div class="comment-website">
                    <a href="${c.website}" target="_blank" rel="noopener noreferrer">🔗 ${c.website}</a>
                </div>` : ''}
                
                <!-- On-Screen Source Inspector for Professor Viva Demonstration -->
                <details class="source-inspector">
                    <summary>🔍 View Delivered HTML Source</summary>
                    <div class="source-code-box">
                        <span class="inspector-label">Delivered by Server to Browser (Unescaped):</span>
                        <pre><code>${escapeForDisplay(renderedHtmlSnippet)}</code></pre>
                        <small class="inspector-hint text-danger">⚠️ The browser's HTML parser encounters raw &lt;script&gt; tags and immediately executes them.</small>
                    </div>
                </details>
            </article>`;
        } else {
            // =========================================================================
            // MITIGATED CODE PATH:
            // Context-Aware Output Encoding is strictly applied:
            // - HTML Body Context: encoder.encodeForHTML() escapes <, >, &, ", ', /
            // - URL Context: encoder.encodeForURL() blocks javascript: pseudo-protocols
            // =========================================================================
            const safeAuthor = encoder.encodeForHTML(c.author);
            const safeContent = encoder.encodeForHTML(c.content);
            const safeWebsite = encoder.encodeForURL(c.website);
            const safeWebsiteLabel = encoder.encodeForHTML(c.website);

            const renderedHtmlSnippet = `<div class="comment-body">\n    ${safeContent}\n</div>`;

            return `
            <article class="comment-card safe-card" id="comment-${c.id}">
                <div class="comment-meta">
                    <span class="comment-author">${safeAuthor}</span>
                    <span class="comment-time">${c.timestamp}</span>
                    <span class="badge badge-safe">Context-Encoded</span>
                </div>
                <div class="comment-body">
                    ${safeContent}
                </div>
                ${c.website ? `
                <div class="comment-website">
                    <a href="${safeWebsite}" target="_blank" rel="noopener noreferrer">🔗 ${safeWebsiteLabel}</a>
                </div>` : ''}
                
                <!-- On-Screen Source Inspector for Professor Viva Demonstration -->
                <details class="source-inspector">
                    <summary>🔍 View Delivered HTML Source</summary>
                    <div class="source-code-box">
                        <span class="inspector-label">Delivered by Server to Browser (Entity-Encoded):</span>
                        <pre><code>${escapeForDisplay(renderedHtmlSnippet)}</code></pre>
                        <small class="inspector-hint text-success">🛡️ Notice how &lt; is encoded to &amp;lt; and &gt; to &amp;gt;. The browser treats them as plain character data and never executes code.</small>
                    </div>
                </details>
            </article>`;
        }
    }).join('\n');

    return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Community Hub | Discussion Forum</title>
    <link rel="stylesheet" href="/public/css/style.css">
</head>
<body>

    <!-- Professional Top Header -->
    <header class="app-header">
        <div class="header-inner">
            <div class="brand">
                <span class="brand-icon">💬</span>
                <span class="brand-name">Community Hub</span>
            </div>
            <div class="mode-switch-wrapper">
                <span class="mode-caption">Security Mode:</span>
                <div class="mode-toggle">
                    <a href="/?mode=vulnerable" class="toggle-btn ${!isMitigated ? 'active-vuln' : ''}">
                        ⚠️ Vulnerable
                    </a>
                    <a href="/?mode=mitigated" class="toggle-btn ${isMitigated ? 'active-mitigated' : ''}">
                        🛡️ Mitigated (Encoded)
                    </a>
                </div>
            </div>
        </div>
    </header>

    <!-- Main Content Container -->
    <main class="page-container">

        <!-- Mode Indicator Bar -->
        <div class="status-banner ${isMitigated ? 'banner-secure' : 'banner-warning'}">
            <span class="status-icon">${isMitigated ? '🛡️' : '⚠️'}</span>
            <div class="status-text">
                <strong>Current State: ${isMitigated ? 'Mitigated Mode (Context-Aware Output Encoding Active)' : 'Vulnerable Mode (Raw Unescaped Output Active)'}</strong>
                <p>${isMitigated ? 'All user comments are converted to HTML character entities (&lt; &gt; &amp;) before rendering. Dangerous tags cannot execute.' : 'User comments are concatenated directly into the HTML document. Injected JavaScript executes immediately.'}</p>
            </div>
        </div>

        ${alertMessage ? `<div class="toast-message">${alertMessage}</div>` : ''}

        <!-- Post Submission Form -->
        <section class="card form-box">
            <h2 class="section-title">Leave a Comment</h2>
            <form action="/comment" method="POST" class="post-form">
                <input type="hidden" name="mode" value="${mode}">
                <div class="form-row">
                    <div class="form-field">
                        <label for="author">Your Name</label>
                        <input type="text" id="author" name="author" placeholder="e.g., Alex Morgan" required>
                    </div>
                    <div class="form-field">
                        <label for="website">Website (Optional)</label>
                        <input type="text" id="website" name="website" placeholder="e.g., https://example.com">
                    </div>
                </div>
                <div class="form-field">
                    <label for="content">Comment</label>
                    <textarea id="content" name="content" rows="3" placeholder="Share your thoughts or enter test input..." required></textarea>
                </div>
                <div class="form-buttons">
                    <button type="submit" class="btn btn-submit">Post Comment</button>
                    <a href="/reset?mode=${mode}" class="btn btn-reset">Reset Comments</a>
                </div>
            </form>
        </section>

        <!-- Comments Feed -->
        <section class="feed-section">
            <div class="feed-header">
                <h2 class="section-title">Discussions (${comments.length})</h2>
            </div>
            <div class="feed-list">
                ${comments.length > 0 ? commentsHtml : '<div class="empty-feed">No comments posted yet.</div>'}
            </div>
        </section>

    </main>

    <footer class="app-footer">
        <p>&copy; 2026 Community Hub. All rights reserved.</p>
    </footer>

</body>
</html>`;
}

/**
 * Basic escaper for author in vulnerable mode to keep author clean while testing content injection
 */
function escapeOnlyAuthor(str) {
    if (!str) return 'Anonymous';
    return String(str).replace(/[<>&]/g, (c) => {
        return c === '<' ? '&lt;' : c === '>' ? '&gt;' : '&amp;';
    });
}

/**
 * Escapes characters solely so they can be shown literally inside <pre><code> debug inspector
 */
function escapeForDisplay(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

module.exports = { renderPage };
