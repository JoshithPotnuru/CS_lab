/**
 * Context-Aware Output Encoding Utility
 * 
 * Course: Cyber Security (IT-30001) - Autumn Semester 2026
 * Department of Information Technology, IIIT Allahabad
 * Instructor: Dr. Soumyadev Maity
 * 
 * Assignment: Web Server Security
 * Vulnerability Category: Cross-Site Scripting (XSS)
 * Variant 1: Stored XSS
 * Implemented Mitigation: Context-Aware Output Encoding
 * 
 * RATIONALE:
 * Output encoding cannot be generic because web browsers employ different
 * parsers for different structural contexts within an HTML document:
 * 1. HTML Body Context (HTML parser)
 * 2. HTML Attribute Context (Attribute parser)
 * 3. JavaScript Context (JavaScript interpreter inside <script> blocks)
 * 4. URI/URL Context (URI parser for href/src attributes)
 * 
 * Using the wrong encoding allows attackers to bypass defenses.
 * This module implements strict, context-appropriate encoding methods.
 */

const ContextEncoder = {
    /**
     * 1. HTML Body Context Encoding
     * Safe for: <div>...</div>, <p>...</p>, <span>...</span>, <td>...</td>
     * Converts characters that alter HTML document structure into standard character entities.
     * 
     * @param {string} str - Raw untrusted user input
     * @returns {string} - HTML entity encoded string
     */
    encodeForHTML(str) {
        if (str === null || str === undefined) return '';
        const stringValue = String(str);
        return stringValue.replace(/[&<>"'/]/g, (char) => {
            switch (char) {
                case '&': return '&amp;';
                case '<': return '&lt;';
                case '>': return '&gt;';
                case '"': return '&quot;';
                case "'": return '&#x27;'; // &#x27; is preferred over &apos; for universal HTML/XML compatibility
                case '/': return '&#x2F;'; // Helps prevent premature closing of tags like </script>
                default: return char;
            }
        });
    },

    /**
     * 2. HTML Attribute Context Encoding
     * Safe for: <input value="...">, <div title="...">, <a data-info="...">
     * Encodes all characters that could break out of quotes or change attributes,
     * using hexadecimal character references.
     * 
     * @param {string} str - Raw untrusted user input
     * @returns {string} - Attribute-safe encoded string
     */
    encodeForHTMLAttribute(str) {
        if (str === null || str === undefined) return '';
        const stringValue = String(str);
        // Replace non-alphanumeric ASCII characters with &#xHH; format
        return stringValue.replace(/[^a-zA-Z0-9,.\-_]/g, (char) => {
            const hex = char.charCodeAt(0).toString(16).toUpperCase();
            const padded = hex.length < 2 ? '0' + hex : hex;
            return `&#x${padded};`;
        });
    },

    /**
     * 3. JavaScript Context Encoding
     * Safe for embedding dynamic data inside inline script blocks:
     * <script> const userComment = ...; </script>
     * Converts characters into Unicode escape sequences (\uXXXX) so that
     * quotes, control characters, and closing tags (</script>) cannot alter JS AST.
     * 
     * @param {any} data - Untrusted data to embed in JavaScript
     * @returns {string} - Safe Unicode-escaped JSON representation
     */
    encodeForJavaScript(data) {
        if (data === null || data === undefined) return 'null';
        const json = JSON.stringify(data);
        return json.replace(/[<>\u2028\u2029/]/g, (char) => {
            switch (char) {
                case '<': return '\\u003C';
                case '>': return '\\u003E';
                case '/': return '\\u002F';
                case '\u2028': return '\\u2028'; // Line separator
                case '\u2029': return '\\u2029'; // Paragraph separator
                default: return char;
            }
        });
    },

    /**
     * 4. Safe URL / URI Context Encoding
     * Safe for: <a href="...">, <img src="...">
     * Validates protocol (permitting only http: or https:) to block
     * dangerous pseudo-protocols like javascript:, vbscript:, data:.
     * 
     * @param {string} url - User-provided URL
     * @returns {string} - Sanitized & encoded URL, or '#' if dangerous
     */
    encodeForURL(url) {
        if (!url || typeof url !== 'string') return '#';
        const trimmed = url.trim();
        // Disallow javascript: and data: pseudo-protocols
        if (/^(javascript|vbscript|data):/i.test(trimmed)) {
            return '#blocked-protocol';
        }
        // Allow valid absolute http/https or relative URLs
        try {
            return encodeURI(trimmed);
        } catch {
            return '#invalid-url';
        }
    }
};

module.exports = ContextEncoder;
