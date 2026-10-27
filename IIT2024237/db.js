/**
 * Persistent Comment Storage Module
 * 
 * Provides database access for comments stored persistently in comments.json.
 */

const fs = require('fs');
const path = require('path');

const DB_FILE = path.join(__dirname, 'comments.json');

const INITIAL_COMMENTS = [
    {
        id: 1,
        author: "Alex Morgan",
        content: "Has anyone reviewed the new service architecture? The response times have improved significantly.",
        website: "https://example.com/alex",
        timestamp: "2026-10-27 10:15:00"
    },
    {
        id: 2,
        author: "Jordan Lee",
        content: "I just deployed the latest styling updates across the dashboard. Let me know if you run into any layout issues.",
        website: "https://example.com/jordan",
        timestamp: "2026-10-27 11:30:20"
    }
];

class CommentDatabase {
    constructor() {
        this.init();
    }

    init() {
        if (!fs.existsSync(DB_FILE)) {
            this.saveData(INITIAL_COMMENTS);
        }
    }

    readData() {
        try {
            const raw = fs.readFileSync(DB_FILE, 'utf-8');
            return JSON.parse(raw);
        } catch (err) {
            console.error("[Database] Error reading database file, restoring defaults:", err);
            this.saveData(INITIAL_COMMENTS);
            return INITIAL_COMMENTS;
        }
    }

    saveData(data) {
        fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2), 'utf-8');
    }

    getAll() {
        return this.readData();
    }

    add({ author, content, website }) {
        const comments = this.readData();
        const newComment = {
            id: Date.now(),
            author: author || "Anonymous User",
            content: content || "",
            website: website || "",
            timestamp: new Date().toISOString().replace('T', ' ').substring(0, 19)
        };
        comments.push(newComment);
        this.saveData(comments);
        return newComment;
    }

    deleteById(id) {
        const comments = this.readData();
        const filtered = comments.filter(c => c.id !== Number(id));
        this.saveData(filtered);
        return filtered.length !== comments.length;
    }

    reset() {
        this.saveData(INITIAL_COMMENTS);
        return INITIAL_COMMENTS;
    }
}

module.exports = new CommentDatabase();
