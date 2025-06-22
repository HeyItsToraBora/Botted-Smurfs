const express = require('express');
const path = require('path');
const cors = require('cors');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const { initDB } = require('./db');
const { loginHandler } = require('./auth');
const { dashboardHandler } = require('./dashboard');
const { createAccountHandler } = require('./auth');
const { AdminOnly, refreshToken, logout } = require('./middleware/auth');
const { limiter, validateLogin, validateCreateAccount, errorHandler, securityHeaders } = require('./middleware/security');
const config = require('./config');
const logger = require('./utils/logger');
const { getDB } = require('./db');
const { initOffersDB, getOffersDB } = require('./offers_db');
const { initCouponsDB, getCouponsDB, updateCouponUsage } = require('./coupons_db');
const { initCartDB, getOrCreateCart, getCart, addItemToCart, removeItemFromCart, getCartTotal, updateItemQuantity, applyCouponToCart, removeCouponFromCart, getAppliedCoupon, updateCartGmail, clearCart, getCartDB } = require('./cart_db');
const fs = require('fs');
const jwt = require('jsonwebtoken');
const { validationResult } = require('express-validator');
const bcrypt = require('bcrypt');
const cryptoDB = require('./back/crypto_db');
const configDB = require('./back/config_db');
const { sendDiscordEmbed } = logger;
const { initPurchasesDB, createPurchase, getPurchaseById, updatePurchaseStatus, updatePaymentConfirmation } = require('./purchases_db');
const helmet = require('helmet');

const app = express();

// Use Helmet to set various security-related HTTP headers
app.use(helmet());

// Authentication middleware
function authenticateToken(req, res, next) {
    try {
        // Check for token in Authorization header
        const authToken = req.headers.authorization?.split(' ')[1];
        // Check for token in cookies
        const cookieToken = req.cookies?.accessToken;
        
        const token = authToken || cookieToken;

        if (!token) {
            return res.status(401).json({ 
                success: false, 
                message: 'No token provided' 
            });
        }

        const decoded = jwt.verify(token, config.JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        logger.error('Authentication error:', error);
        return res.status(401).json({ 
            success: false, 
            message: 'Invalid token' 
        });
    }
}

// Initialize databases
async function initializeDatabases() {
    try {
        await initDB();
        await initOffersDB();
        await initCouponsDB();
        await initCartDB();
        await initPurchasesDB();
        logger.info('All databases initialized successfully');
    } catch (error) {
        logger.error('Error initializing databases:', error);
        process.exit(1);
    }
}

// Initialize databases before starting server
initializeDatabases().then(() => {
// Security middleware
app.use(securityHeaders);
app.use(cors({
    origin: config.CORS_ORIGIN,
    credentials: true
}));
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname))); // Serve static files from root directory

// Session middleware
app.use(session({
    secret: config.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: config.NODE_ENV === 'production',
        httpOnly: true,
        maxAge: config.SESSION_MAX_AGE
    }
}));

// Apply rate limiting to all routes
app.use(limiter);

// Check if user is already authenticated and redirect from login page
app.get('/login.html', (req, res, next) => {
    // Check for token in Authorization header
    const authToken = req.headers.authorization?.split(' ')[1];
    // Check for token in cookies
    const cookieToken = req.cookies?.accessToken;
    
    const token = authToken || cookieToken;
    
    if (token) {
        try {
            jwt.verify(token, config.JWT_SECRET);
            // If token is valid, redirect to home
            return res.redirect('/home.html');
        } catch (error) {
            // If token is invalid, continue to login page
            next();
        }
    } else {
        next();
    }
});

// Routes
app.post('/login', limiter, validateLogin, loginHandler);
app.post('/refresh-token', refreshToken);
app.post('/logout', logout);
app.get('/dashboard', AdminOnly(dashboardHandler));
app.post('/create-account', AdminOnly(createAccountHandler), validateCreateAccount);

// Token verification endpoint
app.post('/verify-token', (req, res) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) {
            return res.status(401).json({ 
                success: false, 
                message: 'No token provided' 
            });
        }

        const decoded = jwt.verify(token, config.JWT_SECRET);
        const db = getDB();

        db.get('SELECT email FROM users WHERE email = ?', [decoded.email], (err, row) => {
            if (err) {
                logger.error('Database error during token verification:', err);
                return res.status(500).json({ 
                    success: false, 
                    message: 'Database error' 
                });
            }

            if (!row) {
                return res.status(401).json({ 
                    success: false, 
                    message: 'User not found' 
                });
            }

            res.json({ 
                success: true, 
                message: 'Token is valid',
                user: { email: row.email }
            });
        });
    } catch (error) {
        logger.error('Token verification error:', error);
        return res.status(401).json({ 
            success: false, 
            message: 'Invalid token' 
        });
    }
});

// New account management endpoints
app.get('/accounts', AdminOnly(async (req, res) => {
    const db = getDB();
    db.all('SELECT id, email, username, discord_username, discord_id, status, is_admin, created_at FROM users', [], (err, rows) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ success: false, message: 'Database error' });
        }
        res.json({ success: true, accounts: rows });
    });
}));

app.post('/update-account/:id', AdminOnly(async (req, res) => {
    const { id } = req.params;
    const { email, username, password, discordUsername, discordId, isAdmin } = req.body;
    const db = getDB();

    try {
        // Hash password if provided
        let hashedPassword;
        if (password) {
            hashedPassword = await bcrypt.hash(password, 10);
        }

        // Convert isAdmin to number
        let isAdminValue;
        if (isAdmin === 1 || isAdmin === '1' || isAdmin === true) {
            isAdminValue = 1;
        } else {
            isAdminValue = 0;
        }

        // Start a transaction
        db.serialize(() => {
            db.run('BEGIN TRANSACTION');

            // Build the update query based on provided fields
            let updateFields = [];
            let params = [];

            if (email) {
                updateFields.push('email = ?');
                params.push(email);
            }
            if (username) {
                updateFields.push('username = ?');
                params.push(username);
            }
            if (hashedPassword) {
                updateFields.push('password = ?');
                params.push(hashedPassword);
            }
            if (discordUsername !== undefined) {
                updateFields.push('discord_username = ?');
                params.push(discordUsername);
            }
            if (discordId !== undefined) {
                updateFields.push('discord_id = ?');
                params.push(discordId);
            }
            if (isAdmin !== undefined) {
                updateFields.push('is_admin = ?');
                params.push(isAdminValue);
            }

            if (updateFields.length === 0) {
                db.run('ROLLBACK');
                return res.status(400).json({ success: false, message: 'No fields to update' });
            }

            params.push(id);
            const query = `UPDATE users SET ${updateFields.join(', ')} WHERE id = ?`;

            db.run(query, params, function(err) {
                if (err) {
                    logger.error(`Database error updating account ${id} by admin ${req.user.email}: ${err.message}`);
                    db.run('ROLLBACK');
                    return res.status(500).json({ success: false, message: 'Database error' });
                }

                // Verify the update
                db.get('SELECT is_admin, email, username FROM users WHERE id = ?', [id], (err, row) => {
                    if (err) {
                        logger.error(`Database error verifying admin status for account ${id} by admin ${req.user.email}: ${err.message}`);
                        db.run('ROLLBACK');
                        return res.status(500).json({ success: false, message: 'Database error' });
                    }

                    if (row.is_admin !== isAdminValue) {
                        logger.error(`Admin status mismatch after update for account ${id} by admin ${req.user.email}. Expected: ${isAdminValue}, Actual: ${row.is_admin}`);
                        db.run('ROLLBACK');
                        return res.status(500).json({ success: false, message: 'Failed to update admin status' });
                    }

                    db.run('COMMIT');
                    logger.info(`Account updated by admin ${req.user.email}: ID ${id}, Email: ${row.email}, Username: ${row.username}, Admin status: ${isAdminValue}`);
                    res.json({ success: true, message: 'Account updated successfully' });
                });
            });
        });
    } catch (error) {
        logger.error(`Error in /update-account/${id} by admin ${req.user.email}: ${error.message}`);
        db.run('ROLLBACK');
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
}));

app.delete('/delete-account/:id', AdminOnly(async (req, res) => {
    const { id } = req.params;
    const db = getDB();

    // First check if the account exists
    db.get('SELECT id, email, username FROM users WHERE id = ?', [id], (err, row) => {
        if (err) {
            logger.error(`Database error checking account ${id} for deletion by admin ${req.user.email}: ${err.message}`);
            return res.status(500).json({ success: false, message: 'Database error' });
        }

        if (!row) {
            logger.warn(`Attempt to delete non-existent account ID: ${id} by admin ${req.user.email}`);
            return res.status(404).json({ success: false, message: 'Account not found' });
        }

        // Store user info before deletion for logging
        const deletedUserInfo = { id: row.id, email: row.email, username: row.username };

        // Delete the account
        db.run('DELETE FROM users WHERE id = ?', [id], function(err) {
            if (err) {
                logger.error(`Database error deleting account ${id} by admin ${req.user.email}: ${err.message}`);
                return res.status(500).json({ success: false, message: 'Database error' });
            }

            logger.info(`Account deleted by admin ${req.user.email}: ID ${deletedUserInfo.id}, Email: ${deletedUserInfo.email}, Username: ${deletedUserInfo.username}`);
            res.json({ success: true, message: 'Account deleted successfully' });
        });
    });
}));

app.post('/update-account-status', AdminOnly(async (req, res) => {
    const { accountId, status, banReason } = req.body;
    const db = getDB();
    
    db.run('UPDATE users SET status = ?, ban_reason = ? WHERE id = ?',
        [status, banReason, accountId],
        function(err) {
            if (err) {
                logger.error(`Database error updating status for account ${accountId} by admin ${req.user.email}: ${err.message}`);
                return res.status(500).json({ success: false, message: 'Database error' });
            }
            logger.info(`Account status changed by admin ${req.user.email}: ID ${accountId}, New status: ${status}, Reason: ${banReason || 'N/A'}`);
            res.json({ success: true, message: 'Account status updated successfully' });
        });
}));

app.get('/account/:id', AdminOnly(async (req, res) => {
    const db = getDB();
    db.get('SELECT id, email, username, status, ban_reason, is_admin FROM users WHERE id = ?',
        [req.params.id],
        (err, row) => {
            if (err) {
                logger.error(`Database error fetching account ${req.params.id} by admin ${req.user.email}: ${err.message}`);
                return res.status(500).json({ success: false, message: 'Database error' });
            }
            if (!row) {
                logger.warn(`Attempt to fetch non-existent account ID: ${req.params.id} by admin ${req.user.email}`);
                return res.status(404).json({ success: false, message: 'Account not found' });
            }
            res.json({ success: true, account: row });
        });
}));

// Protected dashboard route
app.get('/dashboard.html', AdminOnly((req, res) => {
    res.sendFile(path.join(__dirname, 'private', 'dashboard.html'));
}), (err, req, res, next) => {
    // If authentication fails, redirect to login
    if (err.status === 401 || err.status === 403) {
        logger.warn(`Unauthorized access attempt to dashboard from IP: ${req.ip}`);
        res.redirect('/login.html');
    } else {
        next(err);
    }
});

// Offer Management Endpoints
app.post('/offers', AdminOnly(async (req, res) => {
    const { header, description, details, min_quantity, available_servers, img_url, price_per_acc, available_quantity, offer_type } = req.body;
    const offersDb = getOffersDB();

    if (!header || !description || !min_quantity || !price_per_acc || !offer_type) {
        logger.warn(`Admin ${req.user.email} attempted to create an offer with missing required fields.`);
        return res.status(400).json({ success: false, message: 'Header, description, minimum quantity, price, and offer type are required' });
    }

    try {
        offersDb.run(
            'INSERT INTO offers (header, description, details, offer_type, min_quantity, available_servers, img_url, price_per_acc, available_quantity, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)',
            [header, description, details, offer_type, min_quantity, available_servers, img_url, price_per_acc, available_quantity],
            function(err) {
                if (err) {
                    logger.error(`Database error creating offer by admin ${req.user.email}: ${err.message}`);
                    return res.status(500).json({ success: false, message: 'Database error' });
                }
                logger.info(`Offer created by admin ${req.user.email}: ID ${this.lastID}, Header: ${header}, Price: ${price_per_acc}`);
                res.json({ success: true, message: 'Offer created successfully', offerId: this.lastID });
            }
        );
    } catch (error) {
        logger.error(`Error creating offer by admin ${req.user.email}: ${error.message}`);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
}));

// New endpoint to get distinct offer types
app.get('/offer-types', async (req, res) => {
    const offersDb = getOffersDB();
    offersDb.all('SELECT DISTINCT offer_type FROM offers', [], (err, rows) => {
        if (err) {
            logger.error(`Database error fetching offer types: ${err.message}`);
            return res.status(500).json({ success: false, message: 'Database error' });
        }
        const types = rows.map(row => row.offer_type);
        res.json({ success: true, types });
    });
});

// Public endpoint to get all offers
app.get('/offers', async (req, res) => {
    const { type } = req.query; // Get type from query string
    const offersDb = getOffersDB();
    
    let query = 'SELECT id, header, description, details, min_quantity, available_servers, img_url, price_per_acc, available_quantity, created_at, offer_type FROM offers';
    const params = [];

    if (type && type.toLowerCase() !== 'all') {
        query += ' WHERE offer_type = ?';
        params.push(type);
        logger.info(`Fetching offers filtered by type: ${type}`);
    } else {
        logger.info('Fetching all offers.');
    }

    offersDb.all(query, params, (err, rows) => {
        if (err) {
            logger.error(`Database error fetching offers: ${err.message}`);
            return res.status(500).json({ success: false, message: 'Database error' });
        }
        logger.info(`Offers fetched successfully. Number of offers: ${rows.length}`);
        res.json({ success: true, offers: rows });
    });
});

// Admin-only endpoint to get a specific offer
app.get('/offers/:id', AdminOnly(async (req, res) => {
    const { id } = req.params;
    const offersDb = getOffersDB();

    offersDb.get('SELECT id, header, description, details, min_quantity, available_servers, img_url, price_per_acc, available_quantity, created_at FROM offers WHERE id = ?', [id], (err, row) => {
        if (err) {
            logger.error(`Database error fetching offer ${id} by admin ${req.user.email}: ${err.message}`);
            return res.status(500).json({ success: false, message: 'Database error' });
        }
        if (!row) {
            logger.warn(`Attempt to fetch non-existent offer ID: ${id} by admin ${req.user.email}`);
            return res.status(404).json({ success: false, message: 'Offer not found' });
        }
        res.json({ success: true, offer: row });
    });
}));

app.put('/offers/:id', AdminOnly(async (req, res) => {
    const { id } = req.params;
    const { header, description, details, min_quantity, available_servers, img_url, price_per_acc, available_quantity, offer_type } = req.body;
    const offersDb = getOffersDB();

    if (!header || !description || !min_quantity || !price_per_acc || !offer_type) {
        logger.warn(`Admin ${req.user.email} attempted to update offer ${id} with missing required fields.`);
        return res.status(400).json({ success: false, message: 'Header, description, minimum quantity, price, and offer type are required' });
    }

    try {
        offersDb.run(
            'UPDATE offers SET header = ?, description = ?, details = ?, offer_type = ?, min_quantity = ?, available_servers = ?, img_url = ?, price_per_acc = ?, available_quantity = ? WHERE id = ?',
            [header, description, details, offer_type, min_quantity, available_servers, img_url, price_per_acc, available_quantity, id],
            function(err) {
                if (err) {
                    logger.error(`Database error updating offer ${id} by admin ${req.user.email}: ${err.message}`);
                    return res.status(500).json({ success: false, message: 'Database error' });
                }
                if (this.changes === 0) {
                    logger.warn(`Attempt to update non-existent offer ID: ${id} by admin ${req.user.email}`);
                    return res.status(404).json({ success: false, message: 'Offer not found' });
                }
                logger.info(`Offer updated by admin ${req.user.email}: ID ${id}, Header: ${header}, Price: ${price_per_acc}`);
                res.json({ success: true, message: 'Offer updated successfully' });
            }
        );
    } catch (error) {
        logger.error(`Error updating offer ${id} by admin ${req.user.email}: ${error.message}`);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
}));

app.delete('/offers/:id', AdminOnly(async (req, res) => {
    const { id } = req.params;
    const offersDb = getOffersDB();

    offersDb.run('DELETE FROM offers WHERE id = ?', [id], function(err) {
        if (err) {
            logger.error(`Database error deleting offer ${id} by admin ${req.user.email}: ${err.message}`);
            return res.status(500).json({ success: false, message: 'Database error' });
        }
        if (this.changes === 0) {
            logger.warn(`Attempt to delete non-existent offer ID: ${id} by admin ${req.user.email}`);
            return res.status(404).json({ success: false, message: 'Offer not found' });
        }
        logger.info(`Offer deleted by admin ${req.user.email}: ID ${id}`);
        res.json({ success: true, message: 'Offer deleted successfully' });
    });
}));

// Coupon Management Endpoints
app.post('/coupons', AdminOnly(async (req, res) => {
        const { name, discord_id, discord_name, coupon_id, percentage_per_purchase, max_usage } = req.body;
    const couponsDb = getCouponsDB();

    if (!name || !coupon_id || !percentage_per_purchase) {
        logger.warn(`Admin ${req.user.email} attempted to create a coupon with missing required fields.`);
        return res.status(400).json({ success: false, message: 'Name, coupon ID, and percentage per purchase are required' });
    }

    try {
        couponsDb.run(
                'INSERT INTO coupons (name, discord_id, discord_name, coupon_id, percentage_per_purchase, max_usage, created_at) VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)',
                [name, discord_id, discord_name, coupon_id, percentage_per_purchase, max_usage || 999],
            function(err) {
                if (err) {
                    if (err.message.includes('UNIQUE constraint failed: coupons.coupon_id')) {
                        logger.warn(`Admin ${req.user.email} attempted to create a coupon with duplicate coupon ID: ${coupon_id}.`);
                        return res.status(409).json({ success: false, message: 'Coupon ID already exists' });
                    }
                    logger.error(`Database error creating coupon by admin ${req.user.email}: ${err.message}`);
                    return res.status(500).json({ success: false, message: 'Database error' });
                }
                    logger.info(`Coupon created by admin ${req.user.email}: ID ${this.lastID}, Coupon ID: ${coupon_id}, Name: ${name}, Percentage: ${percentage_per_purchase}%, Max Usage: ${max_usage || 999}`);
                res.json({ success: true, message: 'Coupon created successfully', couponId: this.lastID });
            }
        );
    } catch (error) {
        logger.error(`Error creating coupon by admin ${req.user.email}: ${error.message}`);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
}));

app.get('/coupons', AdminOnly(async (req, res) => {
    const couponsDb = getCouponsDB();
    logger.info(`Admin ${req.user.email} attempting to fetch all coupons.`);
        couponsDb.all('SELECT id, name, discord_id, discord_name, coupon_id, percentage_per_purchase, max_usage, times_used, total_discount_amount, last_used_at, created_at FROM coupons', [], (err, rows) => {
        if (err) {
            logger.error(`Database error fetching coupons by admin ${req.user.email}: ${err.message}`);
            return res.status(500).json({ success: false, message: 'Database error' });
        }
        logger.info(`Coupons fetched successfully by admin ${req.user.email}. Number of coupons: ${rows.length}`);
        res.json({ success: true, coupons: rows });
    });
}));

app.get('/coupons/:id', AdminOnly(async (req, res) => {
    const { id } = req.params;
    const couponsDb = getCouponsDB();

        couponsDb.get('SELECT id, name, discord_id, discord_name, coupon_id, percentage_per_purchase, max_usage, times_used, total_discount_amount, last_used_at, created_at FROM coupons WHERE id = ?', [id], (err, row) => {
        if (err) {
            logger.error(`Database error fetching coupon ${id} by admin ${req.user.email}: ${err.message}`);
            return res.status(500).json({ success: false, message: 'Database error' });
        }
        if (!row) {
            logger.warn(`Attempt to fetch non-existent coupon ID: ${id} by admin ${req.user.email}`);
            return res.status(404).json({ success: false, message: 'Coupon not found' });
        }
        res.json({ success: true, coupon: row });
    });
}));

app.put('/coupons/:id', AdminOnly(async (req, res) => {
    const { id } = req.params;
        const { name, discord_id, discord_name, coupon_id, percentage_per_purchase, max_usage } = req.body;
    const couponsDb = getCouponsDB();

    if (!name || !coupon_id || !percentage_per_purchase) {
        logger.warn(`Admin ${req.user.email} attempted to update coupon ${id} with missing required fields.`);
        return res.status(400).json({ success: false, message: 'Name, coupon ID, and percentage per purchase are required' });
    }

    try {
        couponsDb.run(
                'UPDATE coupons SET name = ?, discord_id = ?, discord_name = ?, coupon_id = ?, percentage_per_purchase = ?, max_usage = ? WHERE id = ?',
                [name, discord_id, discord_name, coupon_id, percentage_per_purchase, max_usage || 999, id],
            function(err) {
                if (err) {
                    if (err.message.includes('UNIQUE constraint failed: coupons.coupon_id')) {
                        logger.warn(`Admin ${req.user.email} attempted to update coupon ${id} with duplicate coupon ID: ${coupon_id}.`);
                        return res.status(409).json({ success: false, message: 'Coupon ID already exists' });
                    }
                    logger.error(`Database error updating coupon ${id} by admin ${req.user.email}: ${err.message}`);
                    return res.status(500).json({ success: false, message: 'Database error' });
                }
                if (this.changes === 0) {
                    logger.warn(`Attempt to update non-existent coupon ID: ${id} by admin ${req.user.email}`);
                    return res.status(404).json({ success: false, message: 'Coupon not found' });
                }
                    logger.info(`Coupon updated by admin ${req.user.email}: ID ${id}, Coupon ID: ${coupon_id}, Name: ${name}, Percentage: ${percentage_per_purchase}%, Max Usage: ${max_usage || 999}`);
                res.json({ success: true, message: 'Coupon updated successfully' });
            }
        );
    } catch (error) {
        logger.error(`Error updating coupon ${id} by admin ${req.user.email}: ${error.message}`);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
}));

app.delete('/coupons/:id', AdminOnly(async (req, res) => {
    const { id } = req.params;
    const couponsDb = getCouponsDB();

    couponsDb.run('DELETE FROM coupons WHERE id = ?', [id], function(err) {
        if (err) {
            logger.error(`Database error deleting coupon ${id} by admin ${req.user.email}: ${err.message}`);
            return res.status(500).json({ success: false, message: 'Database error' });
        }
        if (this.changes === 0) {
            logger.warn(`Attempt to delete non-existent coupon ID: ${id} by admin ${req.user.email}`);
            return res.status(404).json({ success: false, message: 'Coupon not found' });
        }
        logger.info(`Coupon deleted by admin ${req.user.email}: ID ${id}`);
        res.json({ success: true, message: 'Coupon deleted successfully' });
    });
}));

// Redirect to login if not authenticated
app.use('/private/*', (req, res) => {
    logger.warn(`Attempt to access private content without authentication from IP: ${req.ip}`);
    res.redirect('/login.html');
});

// Serve home.html only to authenticated users
app.get('/home.html', AdminOnly((req, res) => {
    logger.info(`User accessed home page: ${req.user.email} from IP: ${req.ip}`);
    fs.readFile('home.html', 'utf8', (err, data) => {
        if (err) {
            logger.error(`Error loading home page for user ${req.user.email}: ${err.message}`);
            return res.status(500).send('Error loading home page');
        }
        res.setHeader('Content-Type', 'text/html');
        res.send(data);
    });
}));

// Offer details endpoint
app.get('/offer-details/:offerId', async (req, res) => {
    const { offerId } = req.params;
    const offersDb = getOffersDB();

    offersDb.get('SELECT * FROM offers WHERE id = ?', [offerId], (err, row) => {
        if (err) {
            logger.error(`Database error fetching offer details for ID ${offerId}:`, err);
            return res.status(500).json({ success: false, message: 'Database error' });
        }
        if (!row) {
            return res.status(404).json({ success: false, message: 'Offer not found' });
        }
        res.json({ success: true, offer: row });
    });
});

// Add to cart endpoint
app.post('/add-to-cart', async (req, res) => {
    try {
        const { offerId, offerType, offerName, serverName, quantity, pricePerAccount, gmailToBeSent } = req.body;
        const accessToken = req.headers.authorization?.split(' ')[1];

        if (!accessToken) {
            return res.status(401).json({ success: false, message: 'Unauthorized: No token provided.' });
        }

        const decoded = jwt.verify(accessToken, config.JWT_SECRET);
        const userId = decoded.id; // Assuming the user ID is in the JWT payload

            // Validate required fields
            if (!offerId || !offerName || !serverName || !quantity || !pricePerAccount) {
                return res.status(400).json({ 
                    success: false, 
                    message: 'Missing required fields: offerId, offerName, serverName, quantity, pricePerAccount' 
                });
            }

            // Get minimum quantity and available quantity from offers database
            const offersDb = getOffersDB();
            const offer = await new Promise((resolve, reject) => {
                offersDb.get('SELECT min_quantity, available_quantity FROM offers WHERE id = ?', [offerId], (err, row) => {
                    if (err) reject(err);
                    else resolve(row);
                });
            });

            if (!offer) {
                return res.status(404).json({ success: false, message: 'Offer not found' });
            }

            // Check current cart to see how much of this offer/server is already in cart
            const currentCart = await getCart(userId);
            let currentCartQuantity = 0;
            
            if (currentCart && currentCart.items) {
                // Sum up quantities for items with same offer_id and server_name
                currentCartQuantity = currentCart.items
                    .filter(item => item.offer_id == offerId && item.server_name === serverName)
                    .reduce((sum, item) => sum + item.quantity, 0);
            }

            // Calculate maximum quantity that can be added
            const maxQuantityToAdd = offer.available_quantity - currentCartQuantity;
            
            // Check if requested quantity exceeds what's available to add
            if (quantity > maxQuantityToAdd) {
                return res.status(400).json({ 
                    success: false, 
                    message: `Cannot add ${quantity} items. You already have ${currentCartQuantity} in your cart. Maximum you can add is ${maxQuantityToAdd}.`,
                    currentCartQuantity: currentCartQuantity,
                    availableQuantity: offer.available_quantity,
                    maxQuantityToAdd: maxQuantityToAdd
                });
            }

            // Check if there's anything available to add
            if (maxQuantityToAdd <= 0) {
                return res.status(400).json({ 
                    success: false, 
                    message: `You already have the maximum available quantity (${offer.available_quantity}) of this offer in your cart.`,
                    currentCartQuantity: currentCartQuantity,
                    availableQuantity: offer.available_quantity
                });
            }

            // Ensure quantity is not below minimum
            const finalQuantity = Math.max(quantity, offer.min_quantity);

            const cart = await getOrCreateCart(userId);

        const offerData = {
            offerId: offerId,
                offerType: offerType || 'default', // Provide default if not specified
            offerName: offerName,
            serverName: serverName,
                quantity: finalQuantity,
                minQuantity: offer.min_quantity,
                availableQuantity: offer.available_quantity,
            pricePerAccount: pricePerAccount,
            gmailToBeSent: gmailToBeSent // This can be null
        };

            logger.info(`Adding item to cart: ${JSON.stringify(offerData)}`);

            const cartItemId = await addItemToCart(cart.cart_id, offerData);
            
        res.json({ success: true, message: 'Item added to cart', cartItemId: cartItemId });

    } catch (error) {
        logger.error('Error adding item to cart:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

    // Get full cart contents
    app.get('/cart', async (req, res) => {
    try {
        const accessToken = req.headers.authorization?.split(' ')[1];

        if (!accessToken) {
            return res.status(401).json({ success: false, message: 'Unauthorized: No token provided.' });
        }

        const decoded = jwt.verify(accessToken, config.JWT_SECRET);
            const userId = decoded.id;

            const cart = await getCart(userId);
            const cartTotal = await getCartTotal(userId);
            
            // If cart has items, fetch offer details including images
            if (cart && cart.items && cart.items.length > 0) {
                const offersDb = getOffersDB();
                
                // Fetch offer details for each cart item
                for (let item of cart.items) {
                    try {
                        const offerDetails = await new Promise((resolve, reject) => {
                            offersDb.get('SELECT img_url, min_quantity, available_quantity FROM offers WHERE id = ?', [item.offer_id], (err, row) => {
                                if (err) reject(err);
                                else resolve(row);
                            });
                        });
                        
                        if (offerDetails) {
                            item.img_url = offerDetails.img_url;
                            item.min_quantity = offerDetails.min_quantity;
                            item.available_quantity = offerDetails.available_quantity;
                        }
                    } catch (error) {
                        logger.error(`Error fetching offer details for offer ${item.offer_id}:`, error);
                        // Set default values if offer details can't be fetched
                        item.img_url = null;
                        item.min_quantity = 1;
                        item.available_quantity = 999;
                    }
                }
            }
            
            res.json({ 
                success: true, 
                cart: cart || { items: [] },
                total: cartTotal
            });

        } catch (error) {
            logger.error('Error getting cart contents:', error);
            res.status(500).json({ success: false, message: 'Internal server error' });
        }
    });

    // Public endpoint to validate a coupon code
    app.post('/cart/validate-coupon', async (req, res) => {
        const { couponCode } = req.body;
        const couponsDb = getCouponsDB();

        if (!couponCode) {
            return res.status(400).json({ success: false, message: 'No coupon code provided' });
        }

        couponsDb.get(
            'SELECT * FROM coupons WHERE coupon_id = ?',
            [couponCode],
            (err, row) => {
                if (err) {
                    logger.error('Database error validating coupon:', err);
                    return res.status(500).json({ success: false, message: 'Database error' });
                }
                if (!row) {
                    return res.status(404).json({ success: false, message: 'Invalid coupon' });
                }
                
                // Check if coupon has reached maximum usage
                if (row.times_used >= row.max_usage) {
                    return res.status(400).json({ success: false, message: 'Coupon usage limit reached' });
                }
                
                // You can add more checks here (expiry, usage, etc.)
                res.json({ success: true, coupon: row });
            }
        );
    });

    // Apply coupon to cart
    app.post('/cart/apply-coupon', async (req, res) => {
        try {
            const accessToken = req.headers.authorization?.split(' ')[1];
            const { couponCode } = req.body;

            if (!accessToken) {
                return res.status(401).json({ success: false, message: 'Unauthorized: No token provided.' });
            }

            if (!couponCode) {
                return res.status(400).json({ success: false, message: 'No coupon code provided' });
            }

            const decoded = jwt.verify(accessToken, config.JWT_SECRET);
            const userId = decoded.id;

            // Check if user already has a coupon applied
            const existingCoupon = await getAppliedCoupon(userId);
            if (existingCoupon) {
                return res.status(400).json({ success: false, message: 'A coupon is already applied to your cart. Please remove it first.' });
            }

            // Validate coupon
            const couponsDb = getCouponsDB();
            couponsDb.get(
                'SELECT * FROM coupons WHERE coupon_id = ?',
                [couponCode],
                async (err, coupon) => {
                    if (err) {
                        logger.error('Database error validating coupon:', err);
                        return res.status(500).json({ success: false, message: 'Database error' });
                    }
                    if (!coupon) {
                        return res.status(404).json({ success: false, message: 'Invalid coupon' });
                    }

                    // Check if coupon has reached maximum usage
                    if (coupon.times_used >= coupon.max_usage) {
                        return res.status(400).json({ success: false, message: 'Coupon usage limit reached' });
                    }

                    // Calculate discount amount
                    const cartTotal = await getCartTotal(userId);
                    const discountAmount = cartTotal * (coupon.percentage_per_purchase / 100);

                    // Apply coupon to cart
                    const applied = await applyCouponToCart(userId, coupon.id, discountAmount);
                    if (applied) {
                        // Update coupon usage statistics
                        await updateCouponUsage(coupon.id, discountAmount);
                        
                        res.json({ 
                            success: true, 
                            message: 'Coupon applied successfully',
                            coupon: coupon,
                            discountAmount: discountAmount
                        });
                    } else {
                        res.status(500).json({ success: false, message: 'Failed to apply coupon' });
                    }
                }
            );

        } catch (error) {
            logger.error('Error applying coupon:', error);
            res.status(500).json({ success: false, message: 'Internal server error' });
        }
    });

    // Remove coupon from cart
    app.delete('/cart/remove-coupon', async (req, res) => {
        try {
            const accessToken = req.headers.authorization?.split(' ')[1];

            if (!accessToken) {
                return res.status(401).json({ success: false, message: 'Unauthorized: No token provided.' });
            }

            const decoded = jwt.verify(accessToken, config.JWT_SECRET);
            const userId = decoded.id;

            logger.info(`User ${userId} attempting to remove coupon from cart`);
            
            const removed = await removeCouponFromCart(userId);
            
            logger.info(`Coupon removal result for user ${userId}: ${removed}`);
            
            if (removed) {
                res.json({ success: true, message: 'Coupon removed successfully' });
            } else {
                res.status(500).json({ success: false, message: 'Failed to remove coupon' });
            }

        } catch (error) {
            logger.error('Error removing coupon:', error);
            res.status(500).json({ success: false, message: 'Internal server error' });
        }
    });

    // Get applied coupon info
    app.get('/cart/applied-coupon', async (req, res) => {
        try {
            const accessToken = req.headers.authorization?.split(' ')[1];

            if (!accessToken) {
                return res.status(401).json({ success: false, message: 'Unauthorized: No token provided.' });
            }

            const decoded = jwt.verify(accessToken, config.JWT_SECRET);
            const userId = decoded.id;

            const appliedCoupon = await getAppliedCoupon(userId);
            
            if (appliedCoupon) {
                // Get coupon details
                const couponsDb = getCouponsDB();
                couponsDb.get(
                    'SELECT * FROM coupons WHERE id = ?',
                    [appliedCoupon.applied_coupon_id],
                    (err, coupon) => {
                        if (err) {
                            logger.error('Database error fetching coupon details:', err);
                            return res.status(500).json({ success: false, message: 'Database error' });
                        }
                        if (!coupon) {
                            return res.status(404).json({ success: false, message: 'Coupon not found' });
                        }
                        
                        res.json({ 
                            success: true, 
                            appliedCoupon: {
                                ...appliedCoupon,
                                coupon: coupon
                            }
                        });
                    }
                );
            } else {
                res.json({ success: true, appliedCoupon: null });
            }

        } catch (error) {
            logger.error('Error getting applied coupon:', error);
            res.status(500).json({ success: false, message: 'Internal server error' });
        }
    });

    // Get cart count
    app.get('/cart/count', async (req, res) => {
        try {
            const accessToken = req.headers.authorization?.split(' ')[1];

            if (!accessToken) {
                return res.status(401).json({ success: false, message: 'Unauthorized: No token provided.' });
            }

            const decoded = jwt.verify(accessToken, config.JWT_SECRET);
            const userId = decoded.id;

            // Get cart and count unique offer+server combinations (cart blocks)
            const cart = await getCart(userId);
            if (!cart || !cart.items) {
                return res.json({ success: true, count: 0 });
            }

            // Count unique offer+server combinations
            const uniqueBlocks = new Set();
            cart.items.forEach(item => {
                const blockKey = `${item.offer_id}_${item.server_name}`;
                uniqueBlocks.add(blockKey);
            });

            res.json({ success: true, count: uniqueBlocks.size });

        } catch (error) {
            logger.error('Error getting cart count:', error);
            res.status(500).json({ success: false, message: 'Internal server error' });
        }
    });

    // Helper to generate a slightly modified Gmail address (only one type of change per call)
    function generateStealthGmail(originalEmail) {
        const [username, domain] = originalEmail.split("@");
        if (!domain || domain.toLowerCase() !== "gmail.com") {
            return originalEmail;
        }
        let newUsername = username.split("");
        const operation = Math.floor(Math.random() * 4); // 0-3 random
        if (operation === 0) { // Repeat a letter
            if (newUsername.length > 0) {
                const idx = Math.floor(Math.random() * newUsername.length);
                newUsername.splice(idx, 0, newUsername[idx]);
            }
        } else if (operation === 1) { // Remove a letter
            if (newUsername.length > 2) {
                const idx = Math.floor(Math.random() * newUsername.length);
                newUsername.splice(idx, 1);
            }
        } else if (operation === 2) { // Replace a letter with a nearby one
            const nearby = (char) => {
                const map = {
                    a: "qws", b: "vgh", c: "xdf", d: "ser", e: "wsd", f: "drg", g: "fty", h: "gyu", i: "ujk", 
                    j: "uik", k: "ijl", l: "k;o", m: "njk", n: "bhm", o: "ikl", p: "ol;", q: "was", r: "edf", 
                    s: "awd", t: "rfy", u: "yhj", v: "cfg", w: "qse", x: "zas", y: "tgh", z: "asx"
                };
                const lower = char.toLowerCase();
                if (map[lower]) {
                    const rand = map[lower][Math.floor(Math.random() * map[lower].length)];
                    return char === lower ? rand : rand.toUpperCase();
                }
                return char;
            };
            if (newUsername.length > 0) {
                const idxReplace = Math.floor(Math.random() * newUsername.length);
                newUsername[idxReplace] = nearby(newUsername[idxReplace]);
            }
        } else if (operation === 3) { // Shuffle or change digit sequence
            const digits = [...newUsername.join("").match(/\d+/g) || []];
            if (digits.length > 0) {
                const d = digits[Math.floor(Math.random() * digits.length)];
                let shuffled = d.split("").sort(() => 0.5 - Math.random()).join("");
                newUsername = newUsername.join("").replace(d, shuffled).split("");
            }
        }
        return newUsername.join("") + "@gmail.com";
    }

    // Update gmail for all cart items
    app.put('/cart/update-gmail', async (req, res) => {
        try {
            const accessToken = req.headers.authorization?.split(' ')[1];
            const { gmail } = req.body;

            if (!accessToken) {
                return res.status(401).json({ success: false, message: 'Unauthorized: No token provided.' });
            }

            if (!gmail) {
                return res.status(400).json({ success: false, message: 'No gmail provided' });
            }

            const decoded = jwt.verify(accessToken, config.JWT_SECRET);
            const userId = decoded.id;

            // Generate stealth gmail for saving
            const stealthGmail = generateStealthGmail(gmail);

            const updated = await updateCartGmail(userId, stealthGmail);
            
            if (updated) {
                res.json({ success: true, message: 'Gmail updated for all cart items', gmail_to_be_sent: stealthGmail });
            } else {
                res.status(404).json({ success: false, message: 'No cart items found' });
            }

        } catch (error) {
            logger.error('Error updating cart gmail:', error);
            res.status(500).json({ success: false, message: 'Internal server error' });
        }
    });

    // Update quantity for a specific cart item
    app.put('/cart/item/:id/quantity', authenticateToken, async (req, res) => {
        const userId = req.user.id;
        const itemId = parseInt(req.params.id, 10);
        let { quantity } = req.body;

        if (isNaN(itemId) || typeof quantity !== 'number' || quantity < 0) {
            return res.status(400).json({ success: false, message: 'Invalid input.' });
        }

        const cartDb = getCartDB();
        const offersDb = getOffersDB();

        // First get the cart item details from cart database
        const getCartItemQuery = `SELECT ci.offer_id, ci.quantity FROM cart_items ci WHERE ci.item_id = ? AND ci.cart_id IN (SELECT cart_id FROM carts WHERE user_id = ?)`;
        
        cartDb.get(getCartItemQuery, [itemId, userId], (err, cartItem) => {
            if (err) {
                logger.error(`DB error getting cart item ${itemId}: ${err.message}`);
                return res.status(500).json({ success: false, message: 'Database error.' });
            }

            if (!cartItem) {
                return res.status(404).json({ success: false, message: 'Item not found in cart.' });
            }

            // Now get the offer details from offers database
            const getOfferQuery = `SELECT min_quantity, available_quantity FROM offers WHERE id = ?`;
            
            offersDb.get(getOfferQuery, [cartItem.offer_id], (err, offerDetails) => {
                if (err) {
                    logger.error(`DB error getting offer details for offer ${cartItem.offer_id}: ${err.message}`);
                    return res.status(500).json({ success: false, message: 'Database error.' });
                }

                if (!offerDetails) {
                    return res.status(404).json({ success: false, message: 'Offer not found.' });
                }

                const { min_quantity, available_quantity } = offerDetails;
                let wasLimited = false;

                if (quantity > available_quantity) {
                    quantity = available_quantity;
                    wasLimited = true;
                }

                if (quantity > 0 && quantity < min_quantity) {
                     return res.status(400).json({ success: false, message: `Quantity cannot be less than minimum of ${min_quantity}.`});
                }

                if (quantity === 0) {
                    const deleteQuery = 'DELETE FROM cart_items WHERE item_id = ? AND cart_id IN (SELECT cart_id FROM carts WHERE user_id = ?)';
                    cartDb.run(deleteQuery, [itemId, userId], function(err) {
                        if (err) {
                            logger.error(`Failed to delete cart item ${itemId} for user ${userId}: ${err.message}`);
                            return res.status(500).json({ success: false, message: 'Failed to update cart.' });
                        }
                        return res.json({ success: true, message: 'Item removed from cart.' });
                    });
                } else {
                    const updateQuery = 'UPDATE cart_items SET quantity = ?, total_price = price_per_account * ? WHERE item_id = ? AND cart_id IN (SELECT cart_id FROM carts WHERE user_id = ?)';
                    cartDb.run(updateQuery, [quantity, quantity, itemId, userId], function(err) {
                        if (err) {
                            logger.error(`Failed to update cart item ${itemId} for user ${userId}: ${err.message}`);
                            return res.status(500).json({ success: false, message: 'Failed to update cart.' });
                        }
                        res.json({ success: true, wasLimited, quantity, message: 'Cart updated successfully.' });
                    });
                }
            });
        });
    });

    // Delete a specific cart item
    app.delete('/cart/item/:id', authenticateToken, (req, res) => {
        const userId = req.user.id;
        const itemId = parseInt(req.params.id, 10);

        if (isNaN(itemId)) {
            return res.status(400).json({ success: false, message: 'Invalid item ID.' });
        }

        const cartDb = getCartDB();
        const query = 'DELETE FROM cart_items WHERE item_id = ? AND cart_id IN (SELECT cart_id FROM carts WHERE user_id = ?)';

        cartDb.run(query, [itemId, userId], function(err) {
            if (err) {
                logger.error(`Failed to delete cart item ${itemId} for user ${userId}: ${err.message}`);
                return res.status(500).json({ success: false, message: 'Failed to remove item.' });
            }
            if (this.changes === 0) {
                return res.status(404).json({ success: false, message: 'Item not found in cart.' });
            }
            res.json({ success: true, message: 'Item removed successfully.' });
        });
    });

    app.post('/cart/add', authenticateToken, async (req, res) => {
        const userId = req.user.id;
        const { offer_id, server_name, quantity } = req.body;
        // ... existing code ...
    });

// Error handling middleware
app.use(errorHandler);

// Serve home.html for the root path
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'home.html'));
});

    // --- Crypto API ---
    app.get('/api/crypto/coins', (req, res) => {
        cryptoDB.getCoins((err, coins) => {
            if (err) return res.status(500).json({ success: false, message: 'DB error', error: err.message });
            res.json({ success: true, coins });
        });
    });
    app.post('/api/crypto/coins', (req, res) => {
        const { name, symbol } = req.body;
        if (!name || !symbol) return res.status(400).json({ success: false, message: 'Missing name or symbol' });
        cryptoDB.addCoin(name, symbol, err => {
            if (err) return res.status(500).json({ success: false, message: 'DB error', error: err.message });
            res.json({ success: true });
        });
    });
    app.delete('/api/crypto/coins/:symbol', (req, res) => {
        cryptoDB.removeCoin(req.params.symbol, err => {
            if (err) return res.status(500).json({ success: false, message: 'DB error', error: err.message });
            res.json({ success: true });
        });
    });
    app.get('/api/crypto/networks/:coinSymbol', (req, res) => {
        cryptoDB.getNetworks(req.params.coinSymbol, (err, networks) => {
            if (err) return res.status(500).json({ success: false, message: 'DB error', error: err.message });
            res.json({ success: true, networks });
        });
    });
    app.post('/api/crypto/networks', (req, res) => {
        const { coinSymbol, networkName, address } = req.body;
        if (!coinSymbol || !networkName || !address) return res.status(400).json({ success: false, message: 'Missing fields' });
        cryptoDB.addNetwork(coinSymbol, networkName, address, err => {
            if (err) return res.status(500).json({ success: false, message: 'DB error', error: err.message });
            res.json({ success: true });
        });
    });
    app.delete('/api/crypto/networks/:id', (req, res) => {
        cryptoDB.removeNetwork(req.params.id, err => {
            if (err) return res.status(500).json({ success: false, message: 'DB error', error: err.message });
            res.json({ success: true });
        });
    });
    app.put('/api/crypto/networks/:id', (req, res) => {
        const { address } = req.body;
        if (!address) return res.status(400).json({ success: false, message: 'Missing address' });
        cryptoDB.updateAddress(req.params.id, address, err => {
            if (err) return res.status(500).json({ success: false, message: 'DB error', error: err.message });
            res.json({ success: true });
        });
    });

// --- Config API ---
app.get('/api/config/min-order-price', (req, res) => {
  configDB.getMinOrderPrice((err, value) => {
    if (err) return res.status(500).json({ success: false, message: 'DB error', error: err.message });
    res.json({ success: true, value });
  });
});
app.post('/api/config/min-order-price', (req, res) => {
  const { value } = req.body;
  if (typeof value !== 'number' || isNaN(value)) return res.status(400).json({ success: false, message: 'Invalid value' });
  configDB.setMinOrderPrice(value, err => {
    if (err) return res.status(500).json({ success: false, message: 'DB error', error: err.message });
    res.json({ success: true });
  });
});

// === ADMIN CART MANAGEMENT ENDPOINTS ===
// Get a user's cart (admin)
app.get('/admin/cart/:userId', AdminOnly(async (req, res) => {
    try {
        const userId = parseInt(req.params.userId, 10);
        if (!userId) return res.status(400).json({ success: false, message: 'Invalid userId' });
        const cart = await getCart(userId);
        const cartTotal = await getCartTotal(userId);
        res.json({ success: true, cart: cart || { items: [] }, total: cartTotal });
    } catch (error) {
        logger.error('Admin get user cart error:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
}));

// Add item to user's cart (admin)
app.post('/admin/cart/:userId/add', AdminOnly(async (req, res) => {
    try {
        const userId = parseInt(req.params.userId, 10);
        const { offerId, offerType, offerName, serverName, quantity, pricePerAccount, gmailToBeSent } = req.body;
        if (!offerId || !offerName || !serverName || !quantity || !pricePerAccount) {
            return res.status(400).json({ success: false, message: 'Missing required fields.' });
        }
        const cart = await getOrCreateCart(userId);
        const offerData = { offerId, offerType, offerName, serverName, quantity, pricePerAccount, gmailToBeSent };
        const cartItemId = await addItemToCart(cart.cart_id, offerData);
        res.json({ success: true, message: 'Item added to cart', cartItemId });
    } catch (error) {
        logger.error('Admin add item to user cart error:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
}));

// Update item in user's cart (admin)
app.put('/admin/cart/:userId/item/:itemId', AdminOnly(async (req, res) => {
    try {
        const userId = parseInt(req.params.userId, 10);
        const itemId = parseInt(req.params.itemId, 10);
        const { quantity } = req.body;
        if (!quantity || quantity < 1) return res.status(400).json({ success: false, message: 'Invalid quantity' });
        const updated = await updateItemQuantity(itemId, quantity, userId);
        if (updated) {
            res.json({ success: true, message: 'Item updated' });
        } else {
            res.status(404).json({ success: false, message: 'Item not found in cart' });
        }
    } catch (error) {
        logger.error('Admin update cart item error:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
}));

// Remove item from user's cart (admin)
app.delete('/admin/cart/:userId/item/:itemId', AdminOnly(async (req, res) => {
    try {
        const userId = parseInt(req.params.userId, 10);
        const itemId = parseInt(req.params.itemId, 10);
        const removed = await removeItemFromCart(itemId, userId);
        if (removed) {
            res.json({ success: true, message: 'Item removed from cart' });
        } else {
            res.status(404).json({ success: false, message: 'Item not found in cart' });
        }
    } catch (error) {
        logger.error('Admin remove cart item error:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
}));

// Clear all items from user's cart (admin)
app.delete('/admin/cart/:userId/clear', AdminOnly(async (req, res) => {
    try {
        const userId = parseInt(req.params.userId, 10);
        const cleared = await clearCart(userId);
        res.json({ success: true, message: 'Cart cleared', clearedCount: cleared });
    } catch (error) {
        logger.error('Admin clear user cart error:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
}));

// Remove items from user's cart by server (admin)
app.delete('/admin/cart/:userId/remove/:server', AdminOnly(async (req, res) => {
    try {
        const userId = parseInt(req.params.userId, 10);
        const server = req.params.server;
        
        if (!userId || !server) {
            return res.status(400).json({ success: false, message: 'Invalid userId or server' });
        }

        // Remove all items for this server in one query
        const { getCartDB } = require('./cart_db');
        const cartDb = getCartDB();
        cartDb.run(
            `DELETE FROM cart_items WHERE server_name = ? AND cart_id IN (SELECT cart_id FROM carts WHERE user_id = ?)`,
            [server, userId],
            function(err) {
                if (err) {
                    logger.error('Admin remove items from user cart error:', err);
                    return res.status(500).json({ success: false, message: 'Internal server error' });
                }
                logger.info(`Admin ${req.user.email} removed ${this.changes} items for server ${server} from user ${userId}'s cart`);
                res.json({ success: true, message: 'Items removed successfully', removedCount: this.changes });
            }
        );
    } catch (error) {
        logger.error('Admin remove items from user cart error:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
}));

// === PURCHASE ENDPOINTS ===
// Create a purchase
app.post('/purchase', async (req, res) => {
    try {
        const accessToken = req.headers.authorization?.split(' ')[1];
        if (!accessToken) return res.status(401).json({ success: false, message: 'Unauthorized' });
        const decoded = jwt.verify(accessToken, config.JWT_SECRET);
        const userId = decoded.id;
        const userEmail = decoded.email;
        // Get cart
        const cart = await getCart(userId);
        if (!cart || !cart.items || cart.items.length === 0) {
            return res.status(400).json({ success: false, message: 'Cart is empty' });
        }
        // Get payment info from body
        const { payment_currency, payment_networks, total_before_coupon, coupon_code, coupon_percent, subtotal_after_coupon } = req.body;
        // Validate required fields
        if (!payment_currency || !payment_networks || !Array.isArray(payment_networks) || payment_networks.length === 0 || !total_before_coupon || !subtotal_after_coupon) {
            return res.status(400).json({ success: false, message: 'Missing required payment info' });
        }
        // Get gmail_to_be_sent from the first cart item (all should be the same)
        let gmail_to_be_sent = null;
        if (cart.items && cart.items.length > 0 && cart.items[0].gmail_to_be_sent) {
            gmail_to_be_sent = cart.items[0].gmail_to_be_sent;
        }
        // Create purchase
        const purchaseId = await createPurchase({
            user_id: userId,
            user_email: userEmail,
            items: cart.items,
            payment_currency,
            payment_networks: JSON.stringify(payment_networks),
            total_before_coupon,
            coupon_code,
            coupon_percent,
            subtotal_after_coupon,
            gmail_to_be_sent
        });
        // Do NOT clear cart here
        res.json({ success: true, purchaseId, gmail_to_be_sent });
    } catch (error) {
        logger.error('Error creating purchase:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

// Update purchase status and clear cart if confirmed/declined
app.put('/purchase/:id/status', async (req, res) => {
    try {
        const { status } = req.body;
        const validStatuses = ['pending', 'confirmed', 'declined'];
        if (!validStatuses.includes(status)) {
            return res.status(400).json({ success: false, message: 'Invalid status' });
        }
        const purchase = await getPurchaseById(req.params.id);
        if (!purchase) return res.status(404).json({ success: false, message: 'Purchase not found' });
        await updatePurchaseStatus(req.params.id, status);
        // Only clear cart if status is confirmed or declined
        if (status === 'confirmed' || status === 'declined') {
            await clearCart(purchase.user_id);
        }
        res.json({ success: true });
    } catch (error) {
        logger.error('Error updating purchase status:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

// Get purchase by ID
app.get('/purchase/:id', async (req, res) => {
    try {
        const purchase = await getPurchaseById(req.params.id);
        if (!purchase) return res.status(404).json({ success: false, message: 'Purchase not found' });
        res.json({ success: true, purchase });
    } catch (error) {
        logger.error('Error fetching purchase:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

// Update payment confirmation (user action)
app.put('/purchase/:id/confirm-payment', async (req, res) => {
    try {
        const { payment_confirmation } = req.body;
        if (!['unconfirmed', 'confirmed'].includes(payment_confirmation)) {
            return res.status(400).json({ success: false, message: 'Invalid payment confirmation value' });
        }
        const purchase = await getPurchaseById(req.params.id);
        if (!purchase) return res.status(404).json({ success: false, message: 'Purchase not found' });
        await updatePaymentConfirmation(req.params.id, payment_confirmation);
        res.json({ success: true });
    } catch (error) {
        logger.error('Error updating payment confirmation:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

// List all purchases (admin)
app.get('/admin/purchases', AdminOnly(async (req, res) => {
    try {
        const db = require('./purchases_db').getPurchasesDB();
        db.all('SELECT * FROM purchases ORDER BY created_at DESC', [], (err, rows) => {
            if (err) {
                logger.error('Error fetching purchases:', err);
                return res.status(500).json({ success: false, message: 'Database error' });
            }
            // Parse JSON fields and ensure gmail_to_be_sent is present
            rows.forEach(row => {
                row.items = JSON.parse(row.items);
                row.payment_networks = JSON.parse(row.payment_networks);
                if (!('gmail_to_be_sent' in row)) row.gmail_to_be_sent = null;
            });
            res.json({ success: true, purchases: rows });
        });
    } catch (error) {
        logger.error('Error fetching purchases:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
}));

// === USER PURCHASES ENDPOINT ===
app.get('/my-purchases', async (req, res) => {
    try {
        const accessToken = req.headers.authorization?.split(' ')[1];
        if (!accessToken) return res.status(401).json({ success: false, message: 'Unauthorized' });
        const decoded = jwt.verify(accessToken, config.JWT_SECRET);
        const userId = decoded.id;
        const db = require('./purchases_db').getPurchasesDB();
        db.all('SELECT * FROM purchases WHERE user_id = ? ORDER BY created_at DESC', [userId], (err, rows) => {
            if (err) {
                logger.error('Error fetching user purchases:', err);
                return res.status(500).json({ success: false, message: 'Database error' });
            }
            // Parse JSON fields and ensure gmail_to_be_sent is present
            rows.forEach(row => {
                row.items = JSON.parse(row.items);
                row.payment_networks = JSON.parse(row.payment_networks);
                if (!('gmail_to_be_sent' in row)) row.gmail_to_be_sent = null;
            });
            res.json({ success: true, purchases: rows });
        });
    } catch (error) {
        logger.error('Error fetching user purchases:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

// Start the server
app.listen(config.PORT, () => {
    console.log(`Server running on port ${config.PORT}`);
    logger.info(`Server running on port ${config.PORT}`);
    });
}); 