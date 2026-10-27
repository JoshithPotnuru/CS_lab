/**
 * Web Application Server
 * 
 * Demonstrates:
 * - Stored XSS vulnerability when user comments are rendered without encoding
 * - Mitigation using Context-Aware Output Encoding
 */

const express = require('express');
const cookieParser = require('cookie-parser');
const path = require('path');

const db = require('./db');
const views = require('./views');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());
app.use('/public', express.static(path.join(__dirname, 'public')));

// Session cookie setup
app.use((req, res, next) => {
    const mode = req.query.mode || req.cookies.lab_mode || 'vulnerable';
    const isHttpOnly = (mode === 'mitigated');
    
    if (!req.cookies.sessionId) {
        res.cookie('sessionId', 'sess_9f82c4e1b7a0d48e', {
            httpOnly: isHttpOnly,
            sameSite: 'Lax',
            path: '/'
        });
    }
    next();
});

/**
 * Main Discussion Board
 * Query param: ?mode=vulnerable | ?mode=mitigated
 */
app.get('/', (req, res) => {
    let mode = req.query.mode;
    if (!mode) {
        mode = req.cookies.lab_mode || 'vulnerable';
    } else {
        res.cookie('lab_mode', mode, { httpOnly: false, path: '/' });
    }

    const comments = db.getAll();
    const alertMessage = req.query.msg ? decodeURIComponent(req.query.msg) : null;

    const html = views.renderPage({
        mode,
        comments,
        alertMessage
    });

    res.send(html);
});

/**
 * Post Comment Handler
 */
app.post('/comment', (req, res) => {
    const { author, content, website, mode } = req.body;
    const activeMode = mode || 'vulnerable';

    if (!content || !content.trim()) {
        return res.redirect(`/?mode=${activeMode}&msg=${encodeURIComponent('Comment body cannot be empty.')}`);
    }

    db.add({
        author: author ? author.trim() : 'Anonymous User',
        content: content.trim(),
        website: website ? website.trim() : ''
    });

    res.redirect(`/?mode=${activeMode}&msg=${encodeURIComponent('Comment posted successfully.')}`);
});

/**
 * Reset Comments Handler
 */
app.get('/reset', (req, res) => {
    const mode = req.query.mode || 'vulnerable';
    db.reset();
    res.redirect(`/?mode=${mode}&msg=${encodeURIComponent('Comments reset to initial state.')}`);
});

/**
 * API Endpoint to view raw records
 */
app.get('/api/comments', (req, res) => {
    res.json(db.getAll());
});

// Start Server
app.listen(PORT, () => {
    console.log(`[Community Hub] Server running at http://localhost:${PORT}`);
    console.log(`- Vulnerable Mode: http://localhost:${PORT}/?mode=vulnerable`);
    console.log(`- Mitigated Mode:  http://localhost:${PORT}/?mode=mitigated`);
});
