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
                is_admin BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        await pool.query(`
            CREATE TABLE IF NOT EXISTS groups (
                id SERIAL PRIMARY KEY,
                name VARCHAR(255) UNIQUE NOT NULL,
                description TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        await pool.query(`
            CREATE TABLE IF NOT EXISTS user_groups (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id),
                group_id INTEGER REFERENCES groups(id),
                UNIQUE(user_id, group_id)
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

        // Create admin user if doesn't exist
        const adminCheck = await pool.query('SELECT id FROM users WHERE username = $1', ['REACT']);
        if (adminCheck.rows.length === 0) {
            const hashedPassword = await bcrypt.hash('Robotics', 10);
            await pool.query(
                'INSERT INTO users (username, email, password, is_admin) VALUES ($1, $2, $3, $4)',
                ['REACT', 'admin@reactrobotics.app', hashedPassword, true]
            );
            console.log('Admin user REACT created with password Robotics');
        }

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

// Admin middleware
function requireAdmin(req, res, next) {
    if (!req.session.userId) {
        return res.redirect('/login');
    }
    
    pool.query('SELECT is_admin FROM users WHERE id = $1', [req.session.userId], (err, result) => {
        if (err || !result.rows[0] || !result.rows[0].is_admin) {
            return res.status(403).json({ error: 'Admin access required' });
        }
        next();
    });
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

// Fix database constraints
app.get('/fix-constraints', async (req, res) => {
    try {
        // Make photo_path nullable
        await pool.query('ALTER TABLE submissions ALTER COLUMN photo_path DROP NOT NULL');
        
        res.json({ 
            success: true, 
            message: 'Constraints fixed - photo_path is now nullable'
        });
    } catch (error) {
        res.status(500).json({ error: 'Constraint fix failed: ' + error.message });
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

app.get('/admin', requireAuth, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
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

        // Save to database with placeholder for photo_path (since it's NOT NULL)
        await pool.query(
            'INSERT INTO submissions (user_id, photo_path, photo_url, cloudinary_id, description) VALUES ($1, $2, $3, $4, $5)',
            [req.session.userId, 'cloudinary', result.secure_url, result.public_id, description]
        );
        
        res.json({ success: true });
    } catch (error) {
        console.error('Upload error:', error);
        res.status(500).json({ error: 'Failed to save submission: ' + error.message });
    }
});

app.get('/api/my-submissions', requireAuth, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT DISTINCT s.id, s.user_id, s.photo_url, s.description, s.created_at, u.username
            FROM submissions s
            JOIN users u ON s.user_id = u.id
            WHERE s.user_id IN (
                SELECT ug2.user_id 
                FROM user_groups ug1
                JOIN user_groups ug2 ON ug1.group_id = ug2.group_id
                WHERE ug1.user_id = $1
            ) OR s.user_id = $1
            ORDER BY s.created_at DESC
        `, [req.session.userId]);
        
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

// Admin API routes
app.get('/api/admin/users', requireAdmin, async (req, res) => {
    try {
        const result = await pool.query('SELECT id, username, email, is_admin FROM users ORDER BY username');
        res.json(result.rows);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch users' });
    }
});

app.get('/api/admin/groups', requireAdmin, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT g.*, COUNT(ug.user_id) as member_count
            FROM groups g
            LEFT JOIN user_groups ug ON g.id = ug.group_id
            GROUP BY g.id
            ORDER BY g.name
        `);
        res.json(result.rows);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch groups' });
    }
});

app.post('/api/admin/groups', requireAdmin, async (req, res) => {
    try {
        const { name, description } = req.body;
        const result = await pool.query(
            'INSERT INTO groups (name, description) VALUES ($1, $2) RETURNING id',
            [name, description || '']
        );
        res.json({ success: true, id: result.rows[0].id });
    } catch (error) {
        res.status(500).json({ error: 'Failed to create group' });
    }
});
// Add this to your server.js - temporary fix for REACT user admin status
app.get('/fix-react-admin', async (req, res) => {
    try {
        await pool.query('UPDATE users SET is_admin = true WHERE username = $1', ['REACT']);
        res.json({ 
            success: true, 
            message: 'REACT user admin status updated'
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to update admin status: ' + error.message });
    }
});
app.get('/api/admin/group-members/:groupId', requireAdmin, async (req, res) => {
    try {
        const { groupId } = req.params;
        const result = await pool.query(`
            SELECT u.id, u.username, u.email,
                   CASE WHEN ug.user_id IS NOT NULL THEN true ELSE false END as is_member
            FROM users u
            LEFT JOIN user_groups ug ON u.id = ug.user_id AND ug.group_id = $1
            ORDER BY u.username
        `, [groupId]);
        res.json(result.rows);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch group members' });
    }
});

app.post('/api/admin/add-user-to-group', requireAdmin, async (req, res) => {
    try {
        const { userId, groupId } = req.body;
        await pool.query(
            'INSERT INTO user_groups (user_id, group_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
            [userId, groupId]
        );
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Failed to add user to group' });
    }
});

app.post('/api/admin/remove-user-from-group', requireAdmin, async (req, res) => {
    try {
        const { userId, groupId } = req.body;
        await pool.query(
            'DELETE FROM user_groups WHERE user_id = $1 AND group_id = $2',
            [userId, groupId]
        );
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Failed to remove user from group' });
    }
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});