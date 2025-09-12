const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const { Pool } = require('pg');
const path = require('path');
const bodyParser = require('body-parser');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

// Create uploads directory
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir, { recursive: true });
}

// PostgreSQL connection
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Create tables
async function createTables() {
    try {
        await pool.query(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(255) UNIQUE NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        await pool.query(`
            CREATE TABLE IF NOT EXISTS submissions (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id),
                photo_path VARCHAR(255) NOT NULL,
                description TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        console.log('Database tables created successfully');
    } catch (error) {
        console.error('Error creating tables:', error);
    }
}

// Initialize database
createTables();

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static('public'));
app.use('/uploads', express.static('uploads'));

// Session setup
app.use(session({
    secret: process.env.SESSION_SECRET || 'simple-secret-key-12345',
    resave: false,
    saveUninitialized: false,
    cookie: { 
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
    }
}));

// File upload setup
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/');
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
    }
});

const upload = multer({ 
    storage: storage,
    limits: { fileSize: 5 * 1024 * 1024 }
});

// Auth middleware
function requireAuth(req, res, next) {
    if (req.session.userId) {
        next();
    } else {
        res.redirect('/login');
    }
}

// Routes
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/signup', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'signup.html'));
});

app.get('/submit', requireAuth, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'submit.html'));
});

app.get('/my-submissions', requireAuth, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'submissions.html'));
});

app.get('/scoreboard', requireAuth, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'scoreboard.html'));
});

// Serve uploads statically
app.use('/uploads', express.static(uploadsDir));

// API Routes
app.get('/api/user-info', requireAuth, async (req, res) => {
    try {
        const result = await pool.query('SELECT username FROM users WHERE id = $1', [req.session.userId]);
        if (result.rows.length > 0) {
            res.json({ username: result.rows[0].username });
        } else {
            res.status(404).json({ error: 'User not found' });
        }
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/api/signup', async (req, res) => {
    const { username, email, password } = req.body;
    
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        
        const result = await pool.query(
            'INSERT INTO users (username, email, password) VALUES ($1, $2, $3) RETURNING id',
            [username, email, hashedPassword]
        );
        
        req.session.userId = result.rows[0].id;
        res.json({ success: true });
    } catch (error) {
        if (error.code === '23505') { // Unique violation
            return res.status(400).json({ error: 'Username or email already exists' });
        }
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    
    try {
        const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
        
        if (result.rows.length === 0) {
            return res.status(400).json({ error: 'Invalid credentials' });
        }
        
        const user = result.rows[0];
        const isValidPassword = await bcrypt.compare(password, user.password);
        
        if (!isValidPassword) {
            return res.status(400).json({ error: 'Invalid credentials' });
        }
        
        req.session.userId = user.id;
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/api/logout', (req, res) => {
    req.session.destroy((err) => {
        res.json({ success: true });
    });
});

app.post('/api/submit', requireAuth, upload.single('photo'), async (req, res) => {
    const { description } = req.body;
    const photoPath = req.file ? req.file.filename : null;
    
    if (!photoPath || !description) {
        return res.status(400).json({ error: 'Photo and description are required' });
    }

    try {
        await pool.query(
            'INSERT INTO submissions (user_id, photo_path, description) VALUES ($1, $2, $3)',
            [req.session.userId, photoPath, description]
        );
        
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Failed to save submission' });
    }
});

app.get('/api/my-submissions', requireAuth, async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT * FROM submissions WHERE user_id = $1 ORDER BY created_at DESC',
            [req.session.userId]
        );
        
        res.json(result.rows);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch submissions' });
    }
});

app.get('/api/scoreboard', requireAuth, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT u.username, u.email, 
                   COALESCE(COUNT(s.id), 0) as submission_count,
                   MAX(s.created_at) as last_submission
            FROM users u
            LEFT JOIN submissions s ON u.id = s.user_id
            GROUP BY u.id, u.username, u.email
            ORDER BY submission_count DESC, u.username ASC
        `);
        
        res.json(result.rows);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch scoreboard' });
    }
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});