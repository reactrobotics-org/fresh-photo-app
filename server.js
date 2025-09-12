const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const { Pool } = require('pg');
const cloudinary = require('cloudinary').v2;
const path = require('path');
const bodyParser = require('body-parser');

const app = express();
const PORT = process.env.PORT || 3000;

// Cloudinary configuration
cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});

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
                photo_path TEXT NULL,
                photo_url VARCHAR(500),
                cloudinary_id VARCHAR(255),
                description TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        console.log('Database tables created successfully');
    } catch (error) {
        console.error('Error creating tables:', error);
    }
}

createTables();

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static('public'));

// Session setup
app.use(session({
    secret: process.env.SESSION_SECRET || 'simple-secret-key-12345',
    resave: false,
    saveUninitialized: false,
    cookie: { 
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
    }
}));

// Configure multer for memory storage
const upload = multer({ 
    storage: multer.memoryStorage(),
    limits: { fileSize: 10 * 1024 * 1024 }, // 10MB limit
    fileFilter: function (req, file, cb) {
        const filetypes = /jpeg|jpg|png|gif|webp/;
        const mimetype = filetypes.test(file.mimetype);
        
        if (mimetype) {
            return cb(null, true);
        } else {
            cb(new Error('Only image files are allowed!'));
        }
    }
});

// Helper function to upload to Cloudinary
function uploadToCloudinary(fileBuffer, options = {}) {
    return new Promise((resolve, reject) => {
        cloudinary.uploader.upload_stream(
            {
                resource_type: 'image',
                folder: 'photo-submissions', // Organize photos in a folder
                transformation: [
                    { width: 1200, height: 1200, crop: 'limit' }, // Max size
                    { quality: 'auto:good' } // Auto quality optimization
                ],
                ...options
            },
            (error, result) => {
                if (error) {
                    reject(error);
                } else {
                    resolve(result);
                }
            }
        ).end(fileBuffer);
    });
}

// Auth middleware
function requireAuth(req, res, next) {
    if (req.session.userId) {
        next();
    } else {
        res.redirect('/login');
    }
}

// Temporary migration endpoint
app.get('/migrate-database', async (req, res) => {
    try {
        // Check if photo_url column exists
        const checkColumn = await pool.query(`
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name='submissions' AND column_name='photo_url'
        `);
        
        if (checkColumn.rows.length === 0) {
            // Add new columns
            await pool.query('ALTER TABLE submissions ADD COLUMN photo_url VARCHAR(500)');
            await pool.query('ALTER TABLE submissions ADD COLUMN cloudinary_id VARCHAR(255)');
            
            res.json({ 
                success: true, 
                message: 'Database migrated successfully - added photo_url and cloudinary_id columns'
            });
        } else {
            res.json({ 
                success: true, 
                message: 'Database already has correct columns'
            });
        }
    } catch (error) {
        res.status(500).json({ error: 'Migration failed: ' + error.message });
    }
});

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
        if (error.code === '23505') {
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
    
    if (!req.file || !description) {
        return res.status(400).json({ error: 'Photo and description are required' });
    }

    try {
        console.log('Uploading to Cloudinary...');
        
        // Upload to Cloudinary
        const result = await uploadToCloudinary(req.file.buffer);
        
        console.log('Cloudinary upload successful:', result.public_id);

        // Save to database with Cloudinary URL
        await pool.query(
            'INSERT INTO submissions (user_id, photo_url, cloudinary_id, description) VALUES ($1, $2, $3, $4)',
            [req.session.userId, result.secure_url, result.public_id, description]
        );
        
        res.json({ success: true });
    } catch (error) {
        console.error('Upload error:', error);
        res.status(500).json({ error: 'Failed to save submission: ' + error.message });
    }
});

app.get('/api/my-submissions', requireAuth, async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT id, user_id, COALESCE(photo_url, \'/uploads/\' || photo_path) as photo_url, description, created_at FROM submissions WHERE user_id = $1 ORDER BY created_at DESC',
            [req.session.userId]
        );
        
        res.json(result.rows);
    } catch (error) {
        console.error('Submissions fetch error:', error);
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