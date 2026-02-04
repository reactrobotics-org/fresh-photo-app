const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const { Pool } = require('pg');
const cloudinary = require('cloudinary').v2;
const path = require('path');
const bodyParser = require('body-parser');
const PDFDocument = require('pdfkit');
const axios = require('axios');

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
        } else {
            // Update existing REACT user to be admin
            await pool.query('UPDATE users SET is_admin = true WHERE username = $1', ['REACT']);
            console.log('Updated REACT user to admin status');
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
                folder: 'photo-submissions',
                transformation: [
                    { width: 1200, height: 1200, crop: 'limit' },
                    { quality: 'auto:good' }
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

app.get('/all-submissions', requireAuth, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'all-submissions.html'));
});

app.get('/group-submissions', requireAuth, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'group-submissions.html'));
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
        
        const result = await uploadToCloudinary(req.file.buffer);
        
        console.log('Cloudinary upload successful:', result.public_id);

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

app.get('/api/all-submissions', requireAuth, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT s.id, s.photo_url, s.description, s.created_at, 
                   u.username, u.email
            FROM submissions s
            JOIN users u ON s.user_id = u.id
            ORDER BY s.created_at DESC
        `);
        
        res.json(result.rows);
    } catch (error) {
        console.error('All submissions fetch error:', error);
        res.status(500).json({ error: 'Failed to fetch submissions' });
    }
});

app.get('/api/user-groups', requireAuth, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT g.id, g.name, g.description
            FROM groups g
            JOIN user_groups ug ON g.id = ug.group_id
            WHERE ug.user_id = $1
            ORDER BY g.name
        `, [req.session.userId]);
        
        res.json(result.rows);
    } catch (error) {
        console.error('User groups fetch error:', error);
        res.status(500).json({ error: 'Failed to fetch user groups' });
    }
});

app.get('/api/group-submissions/:groupId', requireAuth, async (req, res) => {
    try {
        const { groupId } = req.params;
        
        const memberCheck = await pool.query(
            'SELECT 1 FROM user_groups WHERE user_id = $1 AND group_id = $2',
            [req.session.userId, groupId]
        );
        
        if (memberCheck.rows.length === 0) {
            return res.status(403).json({ error: 'Not a member of this group' });
        }
        
        const result = await pool.query(`
            SELECT s.id, s.photo_url, s.description, s.created_at,
                   u.username, g.name as group_name
            FROM submissions s
            JOIN users u ON s.user_id = u.id
            JOIN user_groups ug ON u.id = ug.user_id
            JOIN groups g ON ug.group_id = g.id
            WHERE g.id = $1
            ORDER BY s.created_at DESC
        `, [groupId]);
        
        res.json(result.rows);
    } catch (error) {
        console.error('Group submissions fetch error:', error);
        res.status(500).json({ error: 'Failed to fetch group submissions' });
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

// Edit/Delete submission endpoints
app.get('/api/submission/:id', requireAuth, async (req, res) => {
    try {
        const { id } = req.params;
        const result = await pool.query(`
            SELECT s.id, s.photo_url, s.description, s.created_at, u.username
            FROM submissions s
            JOIN users u ON s.user_id = u.id
            WHERE s.id = $1 AND s.user_id = $2
        `, [id, req.session.userId]);
        
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Submission not found or unauthorized' });
        }
        
        res.json(result.rows[0]);
    } catch (error) {
        console.error('Get submission error:', error);
        res.status(500).json({ error: 'Failed to fetch submission' });
    }
});

app.put('/api/submission/:id', requireAuth, async (req, res) => {
    try {
        const { id } = req.params;
        const { description } = req.body;
        
        if (!description || description.trim().length === 0) {
            return res.status(400).json({ error: 'Description is required' });
        }
        
        if (description.length > 500) {
            return res.status(400).json({ error: 'Description must be 500 characters or less' });
        }
        
        const result = await pool.query(`
            UPDATE submissions 
            SET description = $1 
            WHERE id = $2 AND user_id = $3 
            RETURNING id
        `, [description.trim(), id, req.session.userId]);
        
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Submission not found or unauthorized' });
        }
        
        res.json({ success: true });
    } catch (error) {
        console.error('Update submission error:', error);
        res.status(500).json({ error: 'Failed to update submission' });
    }
});

app.delete('/api/submission/:id', requireAuth, async (req, res) => {
    try {
        const { id } = req.params;
        
        const submissionResult = await pool.query(`
            SELECT cloudinary_id 
            FROM submissions 
            WHERE id = $1 AND user_id = $2
        `, [id, req.session.userId]);
        
        if (submissionResult.rows.length === 0) {
            return res.status(404).json({ error: 'Submission not found or unauthorized' });
        }
        
        const cloudinaryId = submissionResult.rows[0].cloudinary_id;
        if (cloudinaryId) {
            try {
                await cloudinary.uploader.destroy(cloudinaryId);
                console.log('Deleted from Cloudinary:', cloudinaryId);
            } catch (cloudinaryError) {
                console.error('Failed to delete from Cloudinary:', cloudinaryError);
            }
        }
        
        await pool.query('DELETE FROM submissions WHERE id = $1 AND user_id = $2', [id, req.session.userId]);
        
        res.json({ success: true });
    } catch (error) {
        console.error('Delete submission error:', error);
        res.status(500).json({ error: 'Failed to delete submission' });
    }
});

// PDF Export endpoint
app.get('/api/export-pdf', requireAuth, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT s.id, s.photo_url, s.description, s.created_at, u.username
            FROM submissions s
            JOIN users u ON s.user_id = u.id
            WHERE s.user_id = $1
            ORDER BY s.created_at DESC
        `, [req.session.userId]);
        
        const submissions = result.rows;
        
        if (submissions.length === 0) {
            return res.status(404).json({ error: 'No submissions to export' });
        }

        const doc = new PDFDocument({
            size: 'letter',
            margins: {
                top: 50,
                bottom: 50,
                left: 50,
                right: 50
            },
            bufferPages: true
        });

        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', `attachment; filename="notebook-entries-${Date.now()}.pdf"`);

        doc.pipe(res);

        // Title page
        doc.fontSize(24)
           .font('Helvetica-Bold')
           .text('Robotics Notebook Entries', { align: 'center' });
        
        doc.moveDown();
        doc.fontSize(14)
           .font('Helvetica')
           .text(`Team Member: ${submissions[0].username}`, { align: 'center' });
        
        doc.fontSize(12)
           .text(`Generated: ${new Date().toLocaleDateString('en-US', { 
               year: 'numeric', 
               month: 'long', 
               day: 'numeric',
               hour: '2-digit',
               minute: '2-digit'
           })}`, { align: 'center' });
        
        doc.moveDown();
        doc.fontSize(10)
           .text(`Total Entries: ${submissions.length}`, { align: 'center' });

        // Don't add a new page yet - start on title page bottom or new page as needed
        let currentPage = 1;
        let isFirstEntry = true;

        for (let i = 0; i < submissions.length; i++) {
            const submission = submissions[i];
            
            const estimatedHeight = 
                30 + 20 + 20 + 30 +
                (Math.ceil(submission.description.length / 80) * 12) +
                200 + 40;
            
            // Check if we need a new page
            if (isFirstEntry || doc.y + estimatedHeight > doc.page.height - 70) {
                if (!isFirstEntry) {
                    // Add page number to current page before moving to next
                    doc.fontSize(9)
                       .fillColor('gray')
                       .text(
                           `Page ${currentPage}`,
                           50,
                           doc.page.height - 50,
                           { align: 'center' }
                       )
                       .fillColor('black');
                }
                
                doc.addPage();
                currentPage++;
                isFirstEntry = false;
            }

            doc.fontSize(14)
               .font('Helvetica-Bold')
               .fillColor('black')
               .text(`Entry ${i + 1} of ${submissions.length}`, { underline: true });
            
            doc.moveDown(0.3);
            
            // Add username
            doc.fontSize(10)
               .font('Helvetica-Bold')
               .text(`Submitted by: ${submission.username}`);
            
            doc.moveDown(0.2);
            
            // Add date
            doc.fontSize(10)
               .font('Helvetica')
               .text(`Date: ${new Date(submission.created_at).toLocaleDateString('en-US', {
                   year: 'numeric',
                   month: 'long',
                   day: 'numeric',
                   hour: '2-digit',
                   minute: '2-digit'
               })}`);
            
            doc.moveDown(0.5);

            if (submission.photo_url) {
                try {
                    console.log('Downloading image:', submission.photo_url);
                    
                    const imageResponse = await axios.get(submission.photo_url, {
                        responseType: 'arraybuffer',
                        timeout: 15000,
                        headers: {
                            'Accept': 'image/*'
                        }
                    });
                    
                    if (imageResponse.status === 200 && imageResponse.data) {
                        const imageBuffer = Buffer.from(imageResponse.data);
                        
                        if (imageBuffer.length > 0) {
                            doc.image(imageBuffer, {
                                fit: [450, 200],
                                align: 'center'
                            });
                            console.log('Image added successfully');
                        } else {
                            throw new Error('Empty image buffer');
                        }
                    }
                    
                    doc.moveDown(0.5);
                } catch (imageError) {
                    console.error('Failed to load image for entry', i, ':', imageError.message);
                    doc.fontSize(9)
                       .fillColor('red')
                       .text('[Image unavailable]', { align: 'center' })
                       .fillColor('black');
                    doc.moveDown(0.5);
                }
            }

            doc.fontSize(10)
               .font('Helvetica-Bold')
               .fillColor('black')
               .text('Description:', { continued: false });
            
            doc.moveDown(0.2);
            
            doc.fontSize(9)
               .font('Helvetica')
               .text(submission.description, {
                   align: 'left',
                   width: 500
               });

            doc.moveDown(1);
            
            if (i < submissions.length - 1) {
                doc.strokeColor('#cccccc')
                   .lineWidth(1)
                   .moveTo(50, doc.y)
                   .lineTo(doc.page.width - 50, doc.y)
                   .stroke();
                
                doc.moveDown(1);
            }
        }

        doc.fontSize(9)
           .fillColor('gray')
           .text(
               `Page ${currentPage}`,
               50,
               doc.page.height - 50,
               { align: 'center' }
           )
           .fillColor('black');

        doc.end();

        console.log('PDF generation completed successfully');

    } catch (error) {
        console.error('PDF export error:', error);
        
        if (!res.headersSent) {
            res.status(500).json({ error: 'Failed to generate PDF: ' + error.message });
        }
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
        console.error('Groups fetch error:', error);
        res.status(500).json({ error: 'Failed to fetch groups' });
    }
});

app.post('/api/admin/groups', requireAdmin, async (req, res) => {
    try {
        console.log('Received request body:', req.body);
        const { groupName, groupDescription } = req.body;
        console.log('Attempting to create group:', groupName, groupDescription);
        
        const result = await pool.query(
            'INSERT INTO groups (name, description) VALUES ($1, $2) RETURNING id',
            [groupName, groupDescription || '']
        );
        
        console.log('Group created successfully:', result.rows[0]);
        res.json({ success: true, id: result.rows[0].id });
    } catch (error) {
        console.error('Group creation error:', error.message);
        console.error('Full error:', error);
        res.status(500).json({ error: 'Failed to create group: ' + error.message });
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

// Get all entries for a specific group
app.get('/api/admin/group-entries/:groupId', requireAdmin, async (req, res) => {
    try {
        const { groupId } = req.params;
        const result = await pool.query(`
            SELECT s.*, u.username, u.email, g.name as group_name
            FROM submissions s
            JOIN users u ON s.user_id = u.id
            JOIN user_groups ug ON u.id = ug.user_id
            JOIN groups g ON ug.group_id = g.id
            WHERE ug.group_id = $1
            ORDER BY s.created_at DESC
        `, [groupId]);
        res.json(result.rows);
    } catch (error) {
        console.error('Group entries fetch error:', error);
        res.status(500).json({ error: 'Failed to fetch group entries' });
    }
});

// Password reset endpoint
app.post('/api/admin/reset-password', requireAdmin, async (req, res) => {
    try {
        const { userId, newPassword } = req.body;
        
        // Validate input
        if (!userId || !newPassword) {
            return res.status(400).json({ error: 'User ID and new password are required' });
        }
        
        if (newPassword.length < 6) {
            return res.status(400).json({ error: 'Password must be at least 6 characters long' });
        }
        
        // Hash the new password
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        
        // Update the user's password
        const result = await pool.query(
            'UPDATE users SET password = $1 WHERE id = $2 RETURNING username',
            [hashedPassword, userId]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        console.log(`Password reset for user: ${result.rows[0].username} by admin`);
        res.json({ success: true, username: result.rows[0].username });
    } catch (error) {
        console.error('Password reset error:', error);
        res.status(500).json({ error: 'Failed to reset password: ' + error.message });
    }
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});