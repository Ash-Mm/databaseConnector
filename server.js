require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise'); // NEW: MySQL client
const multer = require('multer');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const { body, validationResult } = require('express-validator');

const app = express();

// --- Middleware ---

const allowedOrigins = [
    'http://127.0.0.1:5500', // For Live Server in VS Code
    'http://localhost:5000', // For local testing if frontend and backend are on same port
    process.env.FRONTEND_URL // The deployed frontend URL
];

app.use(cors({
    origin: function (origin, callback) {
        if (!origin) return callback(null, true);
        if (allowedOrigins.indexOf(origin) === -1) {
            const msg = 'The CORS policy for this site does not allow access from the specified Origin.';
            return callback(new Error(msg), false);
        }
        return callback(null, true);
    },
    credentials: true
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Ensure uploads directory exists and serve static files from it
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir, { recursive: true });
}
app.use('/uploads', express.static(uploadsDir));

// Serve static files from the 'en' directory
const publicDir = path.join(__dirname, 'en');
if (!fs.existsSync(publicDir)) {
    console.error('❌ "en" directory not found! Please ensure "en" folder exists with your HTML, CSS, JS etc.');
    process.exit(1);
}
app.use(express.static(publicDir));

// --- MySQL Connection Pool ---
let pool; // Declare pool globally

const connectDB = async () => {
    try {
        pool = await mysql.createPool({
            host: process.env.MYSQL_HOST,
            user: process.env.MYSQL_USER,
            password: process.env.MYSQL_PASSWORD,
            database: process.env.MYSQL_DATABASE,
            port: process.env.MYSQL_PORT,
            waitForConnections: true,
            connectionLimit: 10,
            queueLimit: 0
        });
        console.log('✅ MySQL connected successfully');

        // Create news table if it doesn't exist
        await pool.query(`
            CREATE TABLE IF NOT EXISTS news (
                id INT AUTO_INCREMENT PRIMARY KEY,
                title VARCHAR(255) NOT NULL,
                content TEXT NOT NULL,
                image VARCHAR(255),
                video VARCHAR(255),
                createdAt DATETIME DEFAULT CURRENT_TIMESTAMP
            );
        `);
        console.log('✅ News table ensured.');

    } catch (err) {
        console.error('❌ MySQL connection error:', err.message);
        process.exit(1);
    }
};
connectDB();

// --- File Upload Configuration (Multer) ---
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, uploadsDir);
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = `${Date.now()}-${Math.round(Math.random() * 1E9)}`;
        cb(null, `${file.fieldname}-${uniqueSuffix}${path.extname(file.originalname)}`);
    }
});

const fileFilter = (req, file, cb) => {
    if (file.mimetype.startsWith('image/') || file.mimetype.startsWith('video/')) {
        cb(null, true);
    } else {
        cb(new Error('Invalid file type. Only images and videos are allowed!'), false);
    }
};

const upload = multer({
    storage,
    fileFilter,
    limits: { fileSize: 50 * 1024 * 1024 } // 50MB limit
});

// --- Authentication Setup ---
let adminPasswordHash;
(async () => {
    if (!process.env.ADMIN_PASSWORD) {
        console.error('❌ ADMIN_PASSWORD is not set in .env. Server cannot start securely.');
        process.exit(1);
    }
    try {
        adminPasswordHash = await bcrypt.hash(process.env.ADMIN_PASSWORD, 12);
        console.log('Admin password hash generated.');
    } catch (err) {
        console.error('❌ Error hashing admin password:', err.message);
        process.exit(1);
    }
})();

const authenticate = (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ error: 'Unauthorized: No token provided or malformed.' });
        }

        const token = authHeader.split(' ')[1];
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        console.error('Authentication error:', err.message);
        return res.status(401).json({ error: 'Unauthorized: Invalid or expired token.' });
    }
};

// --- API Routes ---

app.post('/login', async (req, res) => {
    try {
        const { password } = req.body;
        if (!password) {
            return res.status(400).json({ error: 'Password is required' });
        }

        // Wait for adminPasswordHash to be generated if it's still null
        if (!adminPasswordHash) {
            let attempts = 0;
            while (!adminPasswordHash && attempts < 10) { // Try up to 1 second
                await new Promise(resolve => setTimeout(resolve, 100));
                attempts++;
            }
            if (!adminPasswordHash) {
                return res.status(500).json({ error: 'Server not ready: Admin password hash not generated.' });
            }
        }

        const match = await bcrypt.compare(password, adminPasswordHash);
        if (!match) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const token = jwt.sign(
            { role: 'admin' },
            process.env.JWT_SECRET,
            { expiresIn: '1h' } // Token expires in 1 hour
        );

        res.json({ token, expiresIn: 3600 });
    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({ error: 'Internal server error during login.' });
    }
});

// Get All News (Publicly accessible) with search and pagination
app.get('/news', async (req, res) => {
    try {
        const { page = 1, limit = 10, search = '', latest = 'false' } = req.query;
        const offset = (parseInt(page) - 1) * parseInt(limit);
        const searchLike = `%${search}%`;

        let query = `
            SELECT id, title, content, image, video, createdAt,
            CONCAT('${process.env.BASE_URL || `http://localhost:${process.env.PORT || 5000}`}/uploads/', image) as imageUrl,
            CONCAT('${process.env.BASE_URL || `http://localhost:${process.env.PORT || 5000}`}/uploads/', video) as videoUrl
            FROM news
        `;
        let countQuery = `SELECT COUNT(*) as total FROM news`;
        const queryParams = [];
        const countQueryParams = [];

        if (search) {
            query += ` WHERE title LIKE ? OR content LIKE ?`;
            countQuery += ` WHERE title LIKE ? OR content LIKE ?`;
            queryParams.push(searchLike, searchLike);
            countQueryParams.push(searchLike, searchLike);
        }

        query += ` ORDER BY createdAt DESC`;

        if (latest === 'true') {
            query += ` LIMIT 5`; // Get only the 5 latest for the side block
        } else {
            query += ` LIMIT ? OFFSET ?`;
            queryParams.push(parseInt(limit), offset);
        }

        const [newsRows] = await pool.query(query, queryParams);
        const [totalRows] = await pool.query(countQuery, countQueryParams);
        const totalArticles = totalRows[0].total;
        const totalPages = latest === 'true' ? 1 : Math.ceil(totalArticles / parseInt(limit));

        res.json({
            success: true,
            data: newsRows,
            total: totalArticles,
            page: parseInt(page),
            pages: totalPages,
            limit: parseInt(limit)
        });
    } catch (err) {
        console.error('Get news error:', err);
        res.status(500).json({ error: 'Failed to fetch news.' });
    }
});

// Get Single News Article (Publicly accessible)
app.get('/news/:id', async (req, res) => {
    try {
        const newsId = req.params.id;
        const [rows] = await pool.query(`
            SELECT id, title, content, image, video, createdAt,
            CONCAT('${process.env.BASE_URL || `http://localhost:${process.env.PORT || 5000}`}/uploads/', image) as imageUrl,
            CONCAT('${process.env.BASE_URL || `http://localhost:${process.env.PORT || 5000}`}/uploads/', video) as videoUrl
            FROM news WHERE id = ?
        `, [newsId]);

        const newsArticle = rows[0];

        if (!newsArticle) {
            return res.status(404).json({ error: 'Article not found.' });
        }

        res.json({ success: true, data: newsArticle });
    } catch (err) {
        console.error('Get single news error:', err);
        res.status(500).json({ error: 'Failed to fetch article.' });
    }
});

// Create New News Article (Admin only)
app.post('/news',
    authenticate,
    upload.fields([
        { name: 'image', maxCount: 1 },
        { name: 'video', maxCount: 1 }
    ]),
    [
        body('title').isLength({ min: 5 }).withMessage('Title must be at least 5 characters').trim().escape(),
        body('content').isLength({ min: 20 }).withMessage('Content must be at least 20 characters').trim().escape(),
        body('newsDate').isISO8601().toDate().withMessage('Invalid date format for Publication Date.') // Validate date
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            // If validation fails, delete any uploaded files
            if (req.files?.image) fs.unlinkSync(req.files.image[0].path);
            if (req.files?.video) fs.unlinkSync(req.files.video[0].path);
            return res.status(400).json({ errors: errors.array() });
        }

        try {
            const { title, content, newsDate } = req.body; // Destructure newsDate
            const imageFilename = req.files?.image?.[0]?.filename || null;
            const videoFilename = req.files?.video?.[0]?.filename || null;

            // newsDate is already a Date object due to isISO8601().toDate()
            const dateToInsert = newsDate;

            const [result] = await pool.query(
                'INSERT INTO news (title, content, image, video, createdAt) VALUES (?, ?, ?, ?, ?)',
                [title, content, imageFilename, videoFilename, dateToInsert]
            );

            const insertedNews = {
                id: result.insertId,
                title,
                content,
                image: imageFilename,
                video: videoFilename,
                createdAt: dateToInsert,
                imageUrl: imageFilename ? `${process.env.BASE_URL || `http://localhost:${process.env.PORT || 5000}`}/uploads/${imageFilename}` : null,
                videoUrl: videoFilename ? `${process.env.BASE_URL || `http://localhost:${process.env.PORT || 5000}`}/uploads/${videoFilename}` : null,
            };

            res.status(201).json({
                success: true,
                message: 'Article created successfully!',
                data: insertedNews
            });
        } catch (err) {
            console.error('Create news error:', err);
            // If DB error, try to delete uploaded files
            if (req.files?.image) fs.unlinkSync(req.files.image[0].path);
            if (req.files?.video) fs.unlinkSync(req.files.video[0].path);
            res.status(500).json({ error: 'Failed to create news: ' + err.message });
        }
    }
);

// Update Existing News Article (Admin only)
app.put('/news/:id',
    authenticate,
    upload.fields([
        { name: 'image', maxCount: 1 },
        { name: 'video', maxCount: 1 }
    ]),
    [
        body('title').optional().isLength({ min: 5 }).withMessage('Title must be at least 5 characters').trim().escape(),
        body('content').optional().isLength({ min: 20 }).withMessage('Content must be at least 20 characters').trim().escape(),
        body('newsDate').optional().isISO8601().toDate().withMessage('Invalid date format for Publication Date.') // Validate date
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            // If validation fails, delete any newly uploaded files
            if (req.files?.image) fs.unlinkSync(req.files.image[0].path);
            if (req.files?.video) fs.unlinkSync(req.files.video[0].path);
            return res.status(400).json({ errors: errors.array() });
        }

        try {
            const newsId = req.params.id;
            const { title, content, clearImage, clearVideo, newsDate } = req.body;

            const [existingNewsRows] = await pool.query('SELECT image, video FROM news WHERE id = ?', [newsId]);
            const existingNews = existingNewsRows[0];

            if (!existingNews) {
                // If article not found, delete any newly uploaded files
                if (req.files?.image) fs.unlinkSync(req.files.image[0].path);
                if (req.files?.video) fs.unlinkSync(req.files.video[0].path);
                return res.status(404).json({ error: 'Article not found for update.' });
            }

            let imageToUpdate = existingNews.image;
            let videoToUpdate = existingNews.video;

            // Handle new image upload or clear request
            if (req.files?.image) {
                if (existingNews.image) fs.unlinkSync(path.join(uploadsDir, existingNews.image));
                imageToUpdate = req.files.image[0].filename;
            } else if (clearImage === 'true') {
                if (existingNews.image) fs.unlinkSync(path.join(uploadsDir, existingNews.image));
                imageToUpdate = null;
            }

            // Handle new video upload or clear request
            if (req.files?.video) {
                if (existingNews.video) fs.unlinkSync(path.join(uploadsDir, existingNews.video));
                videoToUpdate = req.files.video[0].filename;
            } else if (clearVideo === 'true') {
                if (existingNews.video) fs.unlinkSync(path.join(uploadsDir, existingNews.video));
                videoToUpdate = null;
            }

            const updateFields = [];
            const updateValues = [];

            if (title !== undefined) {
                updateFields.push('title = ?');
                updateValues.push(title);
            }
            if (content !== undefined) {
                updateFields.push('content = ?');
                updateValues.push(content);
            }
            if (newsDate !== undefined) { // If newsDate is provided, update it
                updateFields.push('createdAt = ?');
                updateValues.push(newsDate); // newsDate is already a Date object
            }

            // Always update image and video fields, even if null
            updateFields.push('image = ?');
            updateValues.push(imageToUpdate);
            updateFields.push('video = ?');
            updateValues.push(videoToUpdate);

            if (updateFields.length === 0) {
                return res.status(400).json({ error: 'No update data provided.' });
            }

            await pool.query(
                `UPDATE news SET ${updateFields.join(', ')} WHERE id = ?`,
                [...updateValues, newsId]
            );

            // Fetch the updated news to return to the client with virtuals
            const [updatedNewsRows] = await pool.query(`
                SELECT id, title, content, image, video, createdAt,
                    CONCAT('${process.env.BASE_URL || `http://localhost:${process.env.PORT || 5000}`}/uploads/', image) as imageUrl,
                    CONCAT('${process.env.BASE_URL || `http://localhost:${process.env.PORT || 5000}`}/uploads/', video) as videoUrl
                FROM news WHERE id = ?
            `, [newsId]);

            res.json({
                success: true,
                message: 'Article updated successfully!',
                data: updatedNewsRows[0]
            });
        } catch (err) {
            console.error('Update news error:', err);
            // If DB error, try to delete any newly uploaded files
            if (req.files?.image) fs.unlinkSync(req.files.image[0].path);
            if (req.files?.video) fs.unlinkSync(req.files.video[0].path);
            res.status(500).json({ error: 'Failed to update news: ' + err.message });
        }
    }
);

// Delete News Article (Admin only)
app.delete('/news/:id', authenticate, async (req, res) => {
    try {
        const newsId = req.params.id;

        const [existingNewsRows] = await pool.query('SELECT image, video FROM news WHERE id = ?', [newsId]);
        const existingNews = existingNewsRows[0];

        if (!existingNews) {
            return res.status(404).json({ error: 'Article not found.' });
        }

        // Delete associated files from uploads directory
        if (existingNews.image) {
            fs.unlinkSync(path.join(uploadsDir, existingNews.image));
        }
        if (existingNews.video) {
            fs.unlinkSync(path.join(uploadsDir, existingNews.video));
        }

        await pool.query('DELETE FROM news WHERE id = ?', [newsId]);

        res.json({
            success: true,
            message: 'Article deleted successfully!',
            data: existingNews // Return the deleted item data
        });
    } catch (err) {
        console.error('Delete news error:', err);
        res.status(500).json({ error: 'Failed to delete news.' });
    }
});

// --- HTML Route serving (for direct URL access) ---
app.get('/articles', (req, res) => {
    res.sendFile(path.join(publicDir, 'articles.html'));
});

app.get('/single-article', (req, res) => {
    res.sendFile(path.join(publicDir, 'single-article.html'));
});

app.get('/admin', (req, res) => {
    res.sendFile(path.join(publicDir, 'admin.html'));
});

// Serve the main index/articles page for the root route
app.get('/', (req, res) => {
    res.sendFile(path.join(publicDir, 'articles.html'));
});


// --- Error Handling Middleware ---

app.use((err, req, res, next) => {
    console.error('Global error handler caught:', err.stack);

    if (err instanceof multer.MulterError) {
        return res.status(400).json({ error: `File upload error: ${err.message}` });
    }
    if (err.message === 'Invalid file type. Only images and videos are allowed!') {
        return res.status(400).json({ error: err.message });
    }

    res.status(500).json({ error: 'An unexpected error occurred on the server.' });
});

// --- Server Startup ---

const PORT = process.env.PORT || 5000;
app.listen(PORT, '0.0.0.0', () => { // '0.0.0.0' allows connections from any IP, useful for Docker/hosting
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`🔗 Base URL for media: ${process.env.BASE_URL || `http://localhost:${PORT}`}/uploads`);
    console.log(`🌐 Frontend should access API at: ${process.env.BASE_URL || `http://localhost:${PORT}`}`);
});