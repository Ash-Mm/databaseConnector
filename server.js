require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const multer = require('multer');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const { body, validationResult } = require('express-validator');

// --- Cloudinary Configuration (NEW) ---
const cloudinary = require('cloudinary').v2;
cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});
// --- END Cloudinary Config ---

const app = express();

// --- Middleware ---

const allowedOrigins = [
    'http://127.0.0.1:5500', // For local development (VS Code Live Server)
    'http://localhost:5000', // For local development (if frontend served from here)
    process.env.FRONTEND_MAIN_URL,
    process.env.FRONTEND_ADMIN_URL
].filter(Boolean); // Use .filter(Boolean) to remove any undefined/null entries if env vars are missing

app.use(cors({
    origin: function (origin, callback) {
        console.log('CORS Debug: Incoming origin:', origin);
        console.log('CORS Debug: Allowed origins:', allowedOrigins);

        if (!origin || allowedOrigins.includes(origin)) {
            return callback(null, true);
        }
        const msg = 'The CORS policy for this site does not allow access from the specified Origin.';
        return callback(new Error(msg), false);
    },
    credentials: true
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// --- REMOVE local uploads directory serving ---
// You will no longer serve files from a local 'uploads' directory
// The following lines are commented out/removed:
// const uploadsDir = path.join(__dirname, 'uploads');
// if (!fs.existsSync(uploadsDir)) {
//     fs.mkdirSync(uploadsDir, { recursive: true });
// }
// app.use('/uploads', express.static(uploadsDir));
// --- END REMOVED ---


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
        // Note: The `image` and `video` columns will now store Cloudinary URLs directly.
        await pool.query(`
            CREATE TABLE IF NOT EXISTS news (
                id INT AUTO_INCREMENT PRIMARY KEY,
                title VARCHAR(255) NOT NULL,
                content TEXT NOT NULL,
                image VARCHAR(500), -- Increased length for Cloudinary URL
                video VARCHAR(500), -- Increased length for Cloudinary URL
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

// --- File Upload Configuration (Multer) - MODIFIED for Cloudinary ---
// Multer will now store files in memory as buffers, which Cloudinary can then directly upload.
const upload = multer({
    storage: multer.memoryStorage(), // Store files in memory
    fileFilter: (req, file, cb) => {
        if (file.mimetype.startsWith('image/') || file.mimetype.startsWith('video/')) {
            cb(null, true);
        } else {
            cb(new Error('Invalid file type. Only images and videos are allowed!'), false);
        }
    },
    limits: { fileSize: 50 * 1024 * 1024 } // 50MB limit
});

// --- Helper Functions for Cloudinary (NEW) ---

/**
 * Uploads a file buffer to Cloudinary.
 * @param {object} file - The Multer file object (contains buffer and mimetype).
 * @param {string} resourceType - 'image' or 'video'.
 * @param {string} folder - Optional folder name in Cloudinary.
 * @returns {Promise<string>} The Cloudinary URL of the uploaded file.
 */
const uploadToCloudinary = async (file, resourceType, folder = 'hortimed-news') => { // Changed fileBuffer to file
    try {
        const dataUri = `data:${file.mimetype};base64,${file.buffer.toString('base64')}`; // Access file.mimetype and file.buffer
        console.log(`Attempting Cloudinary upload for ${resourceType}. Data URI length: ${dataUri.length}`); // Added console log

        const result = await cloudinary.uploader.upload(dataUri, {
            resource_type: resourceType,
            folder: folder // Organizes uploads in Cloudinary
        });
        return result.secure_url; // Use secure_url for HTTPS
    } catch (error) {
        console.error(`Cloudinary upload error (${resourceType}):`, error);
        throw new Error(`Failed to upload ${resourceType} to Cloudinary.`);
    }
};

/**
 * Deletes a file from Cloudinary using its URL.
 * Extracts public_id from URL to delete.
 * @param {string} fileUrl - The full Cloudinary URL of the file to delete.
 * @param {string} resourceType - 'image' or 'video'.
 * @returns {Promise<void>}
 */
const deleteFromCloudinary = async (fileUrl, resourceType) => {
    if (!fileUrl || !fileUrl.includes('res.cloudinary.com')) {
        // Not a Cloudinary URL, nothing to delete from Cloudinary
        return;
    }
    try {
        // Example URL: https://res.cloudinary.com/cloud_name/image/upload/v12345/folder/public_id.jpg
        const parts = fileUrl.split('/');
        // Find 'upload' or 'video' segment
        const uploadIndex = parts.indexOf('upload');
        if (uploadIndex === -1 || uploadIndex + 1 >= parts.length) {
            console.warn(`Could not extract public_id from Cloudinary URL: ${fileUrl}`);
            return;
        }

        // The public ID starts after 'upload/' and goes until the file extension
        const publicIdWithExtension = parts.slice(uploadIndex + 1).join('/');
        const publicId = publicIdWithExtension.split('.')[0]; // Remove extension

        await cloudinary.uploader.destroy(publicId, { resource_type: resourceType });
        console.log(`Successfully deleted ${publicId} (${resourceType}) from Cloudinary.`);
    } catch (error) {
        console.error(`Error deleting from Cloudinary (${fileUrl}):`, error);
        // Do not throw, as failure to delete from Cloudinary shouldn't stop other operations
    }
};

// --- END Helper Functions ---


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
    console.log('Route hit: POST /login');
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
        console.error('Login error:', err);
        res.status(500).json({ error: 'Internal server error during login.' });
    }
});

// Get All News (Publicly accessible) with search and pagination - MODIFIED for Cloudinary URLs
app.get('/news', async (req, res) => {
    console.log('Route hit: GET /news');
    try {
        console.log('GET /news: Starting query preparation.');
        const { page = 1, limit = 10, search = '', latest = 'false' } = req.query;
        const offset = (parseInt(page) - 1) * parseInt(limit);
        const searchLike = `%${search}%`;

        // No need for CONCAT with BASE_URL anymore; image/video columns now store full URLs
        let query = `
            SELECT id, title, content, image as imageUrl, video as videoUrl, createdAt
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
            query += ` LIMIT 5`;
        } else {
            query += ` LIMIT ? OFFSET ?`;
            queryParams.push(parseInt(limit), offset);
        }

        console.log('GET /news: Executing main query:', query, queryParams);
        const [newsRows] = await pool.query(query, queryParams);
        console.log('GET /news: Main query executed. Number of rows:', newsRows.length);

        console.log('GET /news: Executing count query:', countQuery, countQueryParams);
        const [totalRows] = await pool.query(countQuery, countQueryParams);
        const totalArticles = totalRows[0].total;
        console.log('GET /news: Count query executed. Total articles:', totalArticles);

        const totalPages = latest === 'true' ? 1 : Math.ceil(totalArticles / parseInt(limit));

        console.log('GET /news: Sending JSON response.');
        res.json({
            success: true,
            data: newsRows,
            total: totalArticles,
            page: parseInt(page),
            pages: totalPages,
            limit: parseInt(limit)
        });
    } catch (err) {
        console.error('CRITICAL ERROR: Get news error:', err);
        res.status(500).json({ error: 'Failed to fetch news.' });
    }
});

// Get Single News Article (Publicly accessible) - MODIFIED for Cloudinary URLs
app.get('/news/:id', async (req, res) => {
    console.log('Route hit: GET /news/:id');
    try {
        const newsId = req.params.id;
        // No need for CONCAT with BASE_URL anymore
        const [rows] = await pool.query(`
            SELECT id, title, content, image as imageUrl, video as videoUrl, createdAt
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

// Create New News Article (Admin only) - MODIFIED for Cloudinary uploads
app.post('/news',
    authenticate,
    upload.fields([
        { name: 'image', maxCount: 1 },
        { name: 'video', maxCount: 1 }
    ]),
    [
        body('title').isLength({ min: 5 }).withMessage('Title must be at least 5 characters').trim().escape(),
        body('content').isLength({ min: 20 }).withMessage('Content must be at least 20 characters').trim().escape(),
        body('newsDate').isISO8601().toDate().withMessage('Invalid date format for Publication Date.')
    ],
    async (req, res) => {
        console.log('Route hit: POST /news (create)');
        const errors = validationResult(req);

        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        let imageUrl = null;
        let videoUrl = null;

        try {
            const { title, content, newsDate } = req.body;

            // --- UPLOAD TO CLOUDINARY ---
            if (req.files?.image?.[0]) {
                // Pass the full file object, not just the buffer
                imageUrl = await uploadToCloudinary(req.files.image[0], 'image', 'hortimed-news-images');
            }
            if (req.files?.video?.[0]) {
                // Pass the full file object, not just the buffer
                videoUrl = await uploadToCloudinary(req.files.video[0], 'video', 'hortimed-news-videos');
            }
            // --- END UPLOAD TO CLOUDINARY ---

            const dateToInsert = newsDate;

            // Store the full Cloudinary URLs in the database
            const [result] = await pool.query(
                'INSERT INTO news (title, content, image, video, createdAt) VALUES (?, ?, ?, ?, ?)',
                [title, content, imageUrl, videoUrl, dateToInsert]
            );

            const insertedNews = {
                id: result.insertId,
                title,
                content,
                // These are now the full Cloudinary URLs
                imageUrl: imageUrl,
                videoUrl: videoUrl,
                createdAt: dateToInsert,
            };

            res.status(201).json({
                success: true,
                message: 'Article created successfully!',
                data: insertedNews
            });
        } catch (err) {
            console.error('Create news error:', err);
            // If DB insertion fails, try to delete the files from Cloudinary
            if (imageUrl) await deleteFromCloudinary(imageUrl, 'image');
            if (videoUrl) await deleteFromCloudinary(videoUrl, 'video');
            res.status(500).json({ error: 'Failed to create news: ' + err.message });
        }
    }
);

// Update Existing News Article (Admin only) - MODIFIED for Cloudinary updates
app.put('/news/:id',
    authenticate,
    upload.fields([
        { name: 'image', maxCount: 1 },
        { name: 'video', maxCount: 1 }
    ]),
    [
        body('title').optional().isLength({ min: 5 }).withMessage('Title must be at least 5 characters').trim().escape(),
        body('content').optional().isLength({ min: 20 }).withMessage('Content must be at least 20 characters').trim().escape(),
        body('newsDate').optional().isISO8601().toDate().withMessage('Invalid date format for Publication Date.')
    ],
    async (req, res) => {
        console.log('Route hit: PUT /news/:id (update)');
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        try {
            const newsId = req.params.id;
            const { title, content, clearImage, clearVideo, newsDate } = req.body;

            const [existingNewsRows] = await pool.query('SELECT image, video FROM news WHERE id = ?', [newsId]);
            const existingNews = existingNewsRows[0];

            if (!existingNews) {
                return res.status(404).json({ error: 'Article not found for update.' });
            }

            let imageToUpdate = existingNews.image;
            let videoToUpdate = existingNews.video;

            // --- Handle Image Update ---
            if (req.files?.image?.[0]) {
                if (existingNews.image) {
                    await deleteFromCloudinary(existingNews.image, 'image');
                }
                // Pass the full file object, not just the buffer
                imageToUpdate = await uploadToCloudinary(req.files.image[0], 'image', 'hortimed-news-images');
            } else if (clearImage === 'true') {
                if (existingNews.image) {
                    await deleteFromCloudinary(existingNews.image, 'image');
                }
                imageToUpdate = null;
            }

            // --- Handle Video Update ---
            if (req.files?.video?.[0]) {
                if (existingNews.video) {
                    await deleteFromCloudinary(existingNews.video, 'video');
                }
                // Pass the full file object, not just the buffer
                videoToUpdate = await uploadToCloudinary(req.files.video[0], 'video', 'hortimed-news-videos');
            } else if (clearVideo === 'true') {
                if (existingNews.video) {
                    await deleteFromCloudinary(existingNews.video, 'video');
                }
                videoToUpdate = null;
            }
            // --- END Handle Media Updates ---

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
                updateFields.push('createdAt = ?');
                updateValues.push(newsDate);
            }

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

            const [updatedNewsRows] = await pool.query(`
                SELECT id, title, content, image as imageUrl, video as videoUrl, createdAt
                FROM news WHERE id = ?
            `, [newsId]);

            res.json({
                success: true,
                message: 'Article updated successfully!',
                data: updatedNewsRows[0]
            });
        } catch (err) {
            console.error('Update news error:', err);
            res.status(500).json({ error: 'Failed to update news: ' + err.message });
        }
    }
);

// Delete News Article (Admin only) - MODIFIED for Cloudinary deletion
app.delete('/news/:id', authenticate, async (req, res) => {
    console.log('Route hit: DELETE /news/:id');
    try {
        const newsId = req.params.id;

        const [existingNewsRows] = await pool.query('SELECT image, video FROM news WHERE id = ?', [newsId]);
        const existingNews = existingNewsRows[0];

        if (!existingNews) {
            return res.status(404).json({ error: 'Article not found.' });
        }

        // --- Delete associated files from Cloudinary ---
        if (existingNews.image) {
            await deleteFromCloudinary(existingNews.image, 'image');
        }
        if (existingNews.video) {
            await deleteFromCloudinary(existingNews.video, 'video');
        }
        // --- END Cloudinary Deletion ---

        await pool.query('DELETE FROM news WHERE id = ?', [newsId]);

        res.json({
            success: true,
            message: 'Article deleted successfully!',
            data: existingNews
        });
    } catch (err) {
        console.error('Delete news error:', err);
        res.status(500).json({ error: 'Failed to delete news.' });
    }
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
app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`🌐 Frontend should access API at: ${process.env.BASE_URL || `http://localhost:${PORT}`}`);
});
