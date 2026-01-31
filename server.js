const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const session = require('express-session');
const bodyParser = require('body-parser');
const path = require('path');

const app = express();
const PORT = 3000;

// --- Middleware ---
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
    secret: 'secret-key', // In production, use a secure env variable
    resave: false,
    saveUninitialized: false
}));

// --- Database Setup (SQLite) ---
const db = new sqlite3.Database('./college.db', (err) => {
    if (err) console.error(err.message);
    console.log('Connected to the SQLite database.');
});

// Initialize Tables
db.serialize(() => {
    // Users Table
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        role TEXT CHECK(role IN ('admin', 'faculty'))
    )`);

    // Academic Structure Table (Programs, Depts, etc.)
    db.run(`CREATE TABLE IF NOT EXISTS academic_structure (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        type TEXT, 
        name TEXT
    )`);

    // Content Table (Problems, Contests)
    db.run(`CREATE TABLE IF NOT EXISTS content (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        faculty_id INTEGER,
        type TEXT CHECK(type IN ('problem', 'contest')),
        title TEXT,
        description TEXT,
        status TEXT DEFAULT 'pending',
        FOREIGN KEY(faculty_id) REFERENCES users(id)
    )`);

    // Create a default Admin user (admin/admin123)
    const adminHash = bcrypt.hashSync('admin123', 10);
    db.run(`INSERT OR IGNORE INTO users (username, password, role) VALUES ('admin', ?, 'admin')`, [adminHash]);
});

// --- Routes ---

// 1. Authentication
app.post('/api/register', async (req, res) => {
    const { username, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    // New users are strictly 'faculty' by default in this demo
    db.run(`INSERT INTO users (username, password, role) VALUES (?, ?, 'faculty')`, [username, hashedPassword], function(err) {
        if (err) return res.status(400).json({ error: 'Username already exists' });
        res.json({ message: 'Faculty registered successfully' });
    });
});

app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    db.get(`SELECT * FROM users WHERE username = ?`, [username], async (err, user) => {
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        req.session.userId = user.id;
        req.session.role = user.role;
        res.json({ role: user.role });
    });
});

app.post('/api/logout', (req, res) => {
    req.session.destroy();
    res.json({ message: 'Logged out' });
});

// 2. Admin: Academic Structure
app.post('/api/academic', (req, res) => {
    if (req.session.role !== 'admin') return res.status(403).json({ error: 'Unauthorized' });
    const { type, name } = req.body;
    db.run(`INSERT INTO academic_structure (type, name) VALUES (?, ?)`, [type, name], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ id: this.lastID, type, name });
    });
});

app.get('/api/academic', (req, res) => {
    db.all(`SELECT * FROM academic_structure`, [], (err, rows) => {
        res.json(rows);
    });
});

// 3. Faculty: Create Content (Problem/Contest)
app.post('/api/content', (req, res) => {
    if (req.session.role !== 'faculty') return res.status(403).json({ error: 'Unauthorized' });
    const { type, title, description } = req.body;
    db.run(`INSERT INTO content (faculty_id, type, title, description) VALUES (?, ?, ?, ?)`, 
        [req.session.userId, type, title, description], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: 'Submitted for verification' });
    });
});

// 4. Admin: View & Verify Content
app.get('/api/content/pending', (req, res) => {
    if (req.session.role !== 'admin') return res.status(403).json({ error: 'Unauthorized' });
    db.all(`SELECT c.*, u.username as faculty_name FROM content c JOIN users u ON c.faculty_id = u.id WHERE status = 'pending'`, [], (err, rows) => {
        res.json(rows);
    });
});

app.post('/api/content/verify', (req, res) => {
    if (req.session.role !== 'admin') return res.status(403).json({ error: 'Unauthorized' });
    const { id } = req.body;
    db.run(`UPDATE content SET status = 'verified' WHERE id = ?`, [id], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: 'Content verified' });
    });
});

// 5. Public: View Verified Content (optional check)
app.get('/api/content/verified', (req, res) => {
    db.all(`SELECT * FROM content WHERE status = 'verified'`, [], (err, rows) => {
        res.json(rows);
    });
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});