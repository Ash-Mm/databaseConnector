require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const multer = require('multer');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const stream = require('stream');
const cloudinary = require('cloudinary').v2;

// ==========================================
// 1. Environment Validation
// ==========================================
const REQUIRED_ENV_VARS = [
    'ADMIN_PASSWORD',
    'JWT_SECRET',
    'CLOUDINARY_CLOUD_NAME',
    'CLOUDINARY_API_KEY',
    'CLOUDINARY_API_SECRET',
    'MYSQL_HOST',
    'MYSQL_USER',
    'MYSQL_PASSWORD',
    'MYSQL_DATABASE'
];

const missingEnv = REQUIRED_ENV_VARS.filter(key => !process.env[key]);
if (missingEnv.length > 0) {
    console.error(`❌ Missing required environment variables: ${missingEnv.join(', ')}`);
    process.exit(1);
}

// ==========================================
// 2. Structured Logger
// ==========================================
const logger = {
    info: (msg, meta = {}) => console.log(JSON.stringify({ level: 'info', time: new Date().toISOString(), message: msg, ...meta })),
    error: (msg, meta = {}) => console.error(JSON.stringify({ level: 'error', time: new Date().toISOString(), message: msg, ...meta })),
    warn: (msg, meta = {}) => console.warn(JSON.stringify({ level: 'warn', time: new Date().toISOString(), message: msg, ...meta }))
};

// ==========================================
// 3. Cloudinary Configuration
// ==========================================
cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});

const app = express();

// ==========================================
// 4. Security Middleware (Helmet + Rate Limit)
// ==========================================
app.use(helmet());

const generalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many requests, please try again later.' }
});
app.use(generalLimiter);

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    message: { error: 'Too many login attempts, please try again later.' }
});

// ==========================================
// 5. CORS
// ==========================================
const rawOrigins = [
    'http://127.0.0.1:5500', 
    'http://localhost:5000', 
    'https://hortimed-prima.org',
    'https://www.hortimed-prima.org',
    'https://admin.hortimed-prima.org',
    'https://www.admin.hortimed-prima.org',
    process.env.FRONTEND_MAIN_URL,
    process.env.FRONTEND_ADMIN_URL
];

const allowedOrigins = rawOrigins
    .filter(Boolean)
    .map(url => url.trim().replace(/\/$/, ''));

app.use(cors({
    origin: function (origin, callback) {
        if (!origin || allowedOrigins.includes(origin)) {
            return callback(null, true);
        }
        return callback(null, false);
    },
    credentials: true
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// ==========================================
// 6. MySQL Connection Pool + Auto-Migration
// ==========================================
let pool; 

const connectDB = async () => {
    try {
        pool = mysql.createPool({
            host: process.env.MYSQL_HOST,
            user: process.env.MYSQL_USER,
            password: process.env.MYSQL_PASSWORD,
            database: process.env.MYSQL_DATABASE,
            port: parseInt(process.env.MYSQL_PORT, 10) || 4000, // TiDB default is 4000, not 3306
            waitForConnections: true,
            connectionLimit: 10,
            queueLimit: 0,
            ssl: { rejectUnauthorized: false }
        });

        const connection = await pool.getConnection();
        logger.info('MySQL pool initialized and connected successfully');
        connection.release();

        // --- Safer table creation ---
        await pool.query(`
            CREATE TABLE IF NOT EXISTS news (
                id INT AUTO_INCREMENT PRIMARY KEY,
                title VARCHAR(255) NOT NULL,
                content TEXT NOT NULL,
                image VARCHAR(500), 
                video VARCHAR(500),
                imagePublicId VARCHAR(255),
                videoPublicId VARCHAR(255),
                createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
                publishedAt DATETIME
            );
        `);
        logger.info('News table ensured');

        // --- Safer migrations: check INFORMATION_SCHEMA first ---
        const [columns] = await pool.query(`
            SELECT COLUMN_NAME 
            FROM INFORMATION_SCHEMA.COLUMNS 
            WHERE TABLE_SCHEMA = ? AND TABLE_NAME = 'news'
        `, [process.env.MYSQL_DATABASE]);

        const existingCols = columns.map(c => c.COLUMN_NAME);

        const migrations = [
            { name: 'imagePublicId', def: 'VARCHAR(255)' },
            { name: 'videoPublicId', def: 'VARCHAR(255)' },
            { name: 'publishedAt',   def: 'DATETIME' }
        ];

        for (const col of migrations) {
            if (!existingCols.includes(col.name)) {
                await pool.query(`ALTER TABLE news ADD COLUMN ${col.name} ${col.def}`);
                logger.info(`Migration: added column ${col.name}`);
            } else {
                logger.info(`Migration: column ${col.name} already exists`);
            }
        }

    } catch (err) {
        logger.error('MySQL initialization failed', { error: err.message, code: err.code, sqlState: err.sqlState });
        // DO NOT exit(1) here — let Render show the logs and keep retrying
        throw err;
    }
};
connectDB();

// ==========================================
// 7. File Upload (Multer → Memory)
// ==========================================
const upload = multer({
    storage: multer.memoryStorage(),
    fileFilter: (req, file, cb) => {
        if (file.mimetype.startsWith('image/') || file.mimetype.startsWith('video/')) {
            cb(null, true);
        } else {
            cb(new Error('Invalid file type. Only images and videos are allowed!'), false);
        }
    },
    limits: { fileSize: 50 * 1024 * 1024 }
});

// ==========================================
// 8. Cloudinary Streaming Helpers
// ==========================================
const uploadToCloudinary = (file, resourceType, folder = 'hortimed-news') => {
    return new Promise((resolve, reject) => {
        const uploadStream = cloudinary.uploader.upload_stream(
            { resource_type: resourceType, folder },
            (error, result) => {
                if (error) return reject(error);
                resolve({ url: result.secure_url, publicId: result.public_id });
            }
        );
        
        const bufferStream = new stream.PassThrough();
        bufferStream.end(file.buffer);
        bufferStream.pipe(uploadStream);
        
        bufferStream.on('error', reject);
        uploadStream.on('error', reject);
    });
};

const deleteFromCloudinary = async (publicId, resourceType) => {
    if (!publicId) return;
    try {
        await cloudinary.uploader.destroy(publicId, { resource_type: resourceType });
        logger.info('Cloudinary delete success', { publicId, resourceType });
    } catch (error) {
        logger.error('Cloudinary delete failed', { publicId, resourceType, error: error.message });
    }
};

// ==========================================
// 9. Authentication (Hardened with Role Guard)
// ==========================================
let adminPasswordHash;
(async () => {
    try {
        adminPasswordHash = await bcrypt.hash(process.env.ADMIN_PASSWORD, 12);
        logger.info('Admin password hash generated');
    } catch (err) {
        logger.error('Error hashing admin password', { error: err.message });
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
        
        if (decoded.role !== 'admin') {
            return res.status(403).json({ error: 'Forbidden: Admin access required.' });
        }
        
        req.user = decoded;
        next();
    } catch (err) {
        logger.error('Authentication error', { error: err.message });
        return res.status(401).json({ error: 'Unauthorized: Invalid or expired token.' });
    }
};

// ==========================================
// 10. Centralized Validation Rules
// ==========================================
const createNewsRules = [
    body('title').isLength({ min: 5 }).withMessage('Title must be at least 5 characters').trim().escape(),
    body('content').isLength({ min: 20 }).withMessage('Content must be at least 20 characters').trim().escape(),
    body('newsDate').isISO8601().toDate().withMessage('Invalid date format for Publication Date.')
];

const updateNewsRules = [
    body('title').optional().isLength({ min: 5 }).withMessage('Title must be at least 5 characters').trim().escape(),
    body('content').optional().isLength({ min: 20 }).withMessage('Content must be at least 20 characters').trim().escape(),
    body('newsDate').optional().isISO8601().toDate().withMessage('Invalid date format for Publication Date.')
];

// ==========================================
// 11. API Routes
// ==========================================

// Health Check
app.get('/health', async (req, res) => {
    try {
        const connection = await pool.getConnection();
        connection.release();
        res.json({ status: 'ok', database: 'connected', timestamp: new Date().toISOString() });
    } catch (err) {
        logger.error('Health check failed', { error: err.message });
        res.status(503).json({ status: 'error', database: 'disconnected', timestamp: new Date().toISOString() });
    }
});

// Login
app.post('/login', authLimiter, async (req, res) => {
    logger.info('Route hit: POST /login');
    try {
        const { password } = req.body;
        if (!password) {
            return res.status(400).json({ error: 'Password is required' });
        }

        if (!adminPasswordHash) {
            let attempts = 0;
            while (!adminPasswordHash && attempts < 10) {
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
            { expiresIn: '1h' }
        );

        res.json({ token, expiresIn: 3600 });
    } catch (err) {
        logger.error('Login error', { error: err.message });
        res.status(500).json({ error: 'Internal server error during login.' });
    }
});

// Get All News (publishedAt ordering, no 'latest' flag)
app.get('/news', async (req, res) => {
    logger.info('Route hit: GET /news');
    try {
        const { page = 1, limit = 10, search = '' } = req.query;
        const offset = (parseInt(page) - 1) * parseInt(limit);
        const searchLike = `%${search}%`;

        let query = `
            SELECT id, title, content, image as imageUrl, video as videoUrl, createdAt, publishedAt
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

        query += ` ORDER BY COALESCE(publishedAt, createdAt) DESC`;
        query += ` LIMIT ? OFFSET ?`;
        queryParams.push(parseInt(limit), offset);

        const [newsRows] = await pool.query(query, queryParams);
        const [totalRows] = await pool.query(countQuery, countQueryParams);
        const totalArticles = totalRows[0].total;
        const totalPages = Math.ceil(totalArticles / parseInt(limit));

        res.json({
            success: true,
            data: newsRows,
            total: totalArticles,
            page: parseInt(page),
            pages: totalPages,
            limit: parseInt(limit)
        });
    } catch (err) {
        logger.error('Get news error', { error: err.message });
        res.status(500).json({ error: 'Failed to fetch news.' });
    }
});

// Get Single News Article
app.get('/news/:id', async (req, res) => {
    logger.info('Route hit: GET /news/:id');
    try {
        const newsId = req.params.id;
        const [rows] = await pool.query(`
            SELECT id, title, content, image as imageUrl, video as videoUrl, createdAt, publishedAt
            FROM news WHERE id = ?
        `, [newsId]);

        const newsArticle = rows[0];

        if (!newsArticle) {
            return res.status(404).json({ error: 'Article not found.' });
        }

        res.json({ success: true, data: newsArticle });
    } catch (err) {
        logger.error('Get single news error', { error: err.message });
        res.status(500).json({ error: 'Failed to fetch article.' });
    }
});

// Create New News Article (stores publicId + publishedAt)
app.post('/news',
    authenticate,
    upload.fields([
        { name: 'image', maxCount: 1 },
        { name: 'video', maxCount: 1 }
    ]),
    createNewsRules,
    async (req, res) => {
        logger.info('Route hit: POST /news (create)');
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        let imageUrl = null;
        let imagePublicId = null;
        let videoUrl = null;
        let videoPublicId = null;

        try {
            const { title, content, newsDate } = req.body;

            if (req.files?.image?.[0]) {
                const result = await uploadToCloudinary(req.files.image[0], 'image', 'hortimed-news-images');
                imageUrl = result.url;
                imagePublicId = result.publicId;
            }
            if (req.files?.video?.[0]) {
                const result = await uploadToCloudinary(req.files.video[0], 'video', 'hortimed-news-videos');
                videoUrl = result.url;
                videoPublicId = result.publicId;
            }

            const [result] = await pool.query(
                'INSERT INTO news (title, content, image, imagePublicId, video, videoPublicId, createdAt, publishedAt) VALUES (?, ?, ?, ?, ?, ?, NOW(), ?)',
                [title, content, imageUrl, imagePublicId, videoUrl, videoPublicId, newsDate]
            );

            const insertedNews = {
                id: result.insertId,
                title,
                content,
                imageUrl,
                videoUrl,
                createdAt: new Date(),
                publishedAt: newsDate
            };

            res.status(201).json({
                success: true,
                message: 'Article created successfully!',
                data: insertedNews
            });
        } catch (err) {
            logger.error('Create news error', { error: err.message });
            if (imagePublicId) await deleteFromCloudinary(imagePublicId, 'image');
            if (videoPublicId) await deleteFromCloudinary(videoPublicId, 'video');
            res.status(500).json({ error: 'Failed to create news: ' + err.message });
        }
    }
);

// Update Existing News Article
app.put('/news/:id',
    authenticate,
    upload.fields([
        { name: 'image', maxCount: 1 },
        { name: 'video', maxCount: 1 }
    ]),
    updateNewsRules,
    async (req, res) => {
        logger.info('Route hit: PUT /news/:id (update)');
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        try {
            const newsId = req.params.id;
            const { title, content, clearImage, clearVideo, newsDate } = req.body;

            const [existingNewsRows] = await pool.query(
                'SELECT image, imagePublicId, video, videoPublicId FROM news WHERE id = ?', 
                [newsId]
            );
            const existingNews = existingNewsRows[0];

            if (!existingNews) {
                return res.status(404).json({ error: 'Article not found for update.' });
            }

            let imageToUpdate = existingNews.image;
            let imagePublicIdToUpdate = existingNews.imagePublicId;
            let videoToUpdate = existingNews.video;
            let videoPublicIdToUpdate = existingNews.videoPublicId;

            if (req.files?.image?.[0]) {
                if (existingNews.imagePublicId) {
                    await deleteFromCloudinary(existingNews.imagePublicId, 'image');
                }
                const result = await uploadToCloudinary(req.files.image[0], 'image', 'hortimed-news-images');
                imageToUpdate = result.url;
                imagePublicIdToUpdate = result.publicId;
            } else if (clearImage === 'true') {
                if (existingNews.imagePublicId) {
                    await deleteFromCloudinary(existingNews.imagePublicId, 'image');
                }
                imageToUpdate = null;
                imagePublicIdToUpdate = null;
            }

            if (req.files?.video?.[0]) {
                if (existingNews.videoPublicId) {
                    await deleteFromCloudinary(existingNews.videoPublicId, 'video');
                }
                const result = await uploadToCloudinary(req.files.video[0], 'video', 'hortimed-news-videos');
                videoToUpdate = result.url;
                videoPublicIdToUpdate = result.publicId;
            } else if (clearVideo === 'true') {
                if (existingNews.videoPublicId) {
                    await deleteFromCloudinary(existingNews.videoPublicId, 'video');
                }
                videoToUpdate = null;
                videoPublicIdToUpdate = null;
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
            if (newsDate !== undefined) {
                updateFields.push('publishedAt = ?');
                updateValues.push(newsDate);
            }

            updateFields.push('image = ?', 'imagePublicId = ?', 'video = ?', 'videoPublicId = ?');
            updateValues.push(imageToUpdate, imagePublicIdToUpdate, videoToUpdate, videoPublicIdToUpdate);

            if (updateFields.length === 0) {
                return res.status(400).json({ error: 'No update data provided.' });
            }

            await pool.query(
                `UPDATE news SET ${updateFields.join(', ')} WHERE id = ?`,
                [...updateValues, newsId]
            );

            const [updatedNewsRows] = await pool.query(`
                SELECT id, title, content, image as imageUrl, video as videoUrl, createdAt, publishedAt
                FROM news WHERE id = ?
            `, [newsId]);

            res.json({
                success: true,
                message: 'Article updated successfully!',
                data: updatedNewsRows[0]
            });
        } catch (err) {
            logger.error('Update news error', { error: err.message });
            res.status(500).json({ error: 'Failed to update news: ' + err.message });
        }
    }
);

// Delete News Article (uses stored publicId)
app.delete('/news/:id', authenticate, async (req, res) => {
    logger.info('Route hit: DELETE /news/:id');
    try {
        const newsId = req.params.id;

        const [existingNewsRows] = await pool.query(
            'SELECT imagePublicId, videoPublicId FROM news WHERE id = ?', 
            [newsId]
        );
        const existingNews = existingNewsRows[0];

        if (!existingNews) {
            return res.status(404).json({ error: 'Article not found.' });
        }

        if (existingNews.imagePublicId) {
            await deleteFromCloudinary(existingNews.imagePublicId, 'image');
        }
        if (existingNews.videoPublicId) {
            await deleteFromCloudinary(existingNews.videoPublicId, 'video');
        }

        await pool.query('DELETE FROM news WHERE id = ?', [newsId]);

        res.json({
            success: true,
            message: 'Article deleted successfully!',
            data: { id: newsId }
        });
    } catch (err) {
        logger.error('Delete news error', { error: err.message });
        res.status(500).json({ error: 'Failed to delete news.' });
    }
});

// ==========================================
// 12. 404 Handler
// ==========================================
app.use((req, res) => {
    res.status(404).json({ error: 'Route not found.' });
});

// ==========================================
// 13. Global Error Handler
// ==========================================
app.use((err, req, res, next) => {
    logger.error('Global error handler caught', { error: err.message, stack: err.stack });

    if (err instanceof multer.MulterError) {
        return res.status(400).json({ error: `File upload error: ${err.message}` });
    }
    if (err.message === 'Invalid file type. Only images and videos are allowed!') {
        return res.status(400).json({ error: err.message });
    }

    res.status(500).json({ error: 'An unexpected error occurred on the server.' });
});

// ==========================================
// 14. Process-Level Error Handlers
// ==========================================
process.on('uncaughtException', (err) => {
    logger.error('Uncaught Exception', { error: err.message, stack: err.stack });
    setTimeout(() => process.exit(1), 1000);
});

process.on('unhandledRejection', (reason) => {
    logger.error('Unhandled Rejection', { reason: reason?.message || reason });
});

// ==========================================
// Server Startup
// ==========================================
const PORT = process.env.PORT || 5000;
app.listen(PORT, '0.0.0.0', () => {
    logger.info('Server started', { port: PORT, baseUrl: process.env.BASE_URL || `http://localhost:${PORT}` });
});