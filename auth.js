const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { getDB } = require('./db');
const config = require('./config');
const logger = require('./utils/logger');
const { generateTokens } = require('./middleware/auth');

async function loginHandler(req, res) {
    if (req.method !== 'POST') {
        return res.status(405).json({ success: false, message: 'Method not allowed' });
    }

    const { email, password } = req.body;
    logger.info(`Login attempt for email: ${email} from IP: ${req.ip}`);

    if (!email || !password) {
        logger.warn(`Failed login attempt for email: ${email} - Missing credentials.`);
        return res.status(400).json({ success: false, message: 'Email and password are required' });
    }

    const db = getDB();

    db.get('SELECT * FROM users WHERE email = ?', [email], async (err, row) => {
        if (err) {
            logger.error(`Database error during login for email ${email}: ${err.message}`);
            return res.status(500).json({ success: false, message: 'Database error' });
        }

        if (!row) {
            logger.warn(`Failed login attempt for email: ${email} - User not found.`);
            return res.status(401).json({ success: false, message: 'Invalid email or password' });
        }

        try {
            const match = await bcrypt.compare(password, row.password);
            
            if (!match) {
                logger.warn(`Failed login attempt for email: ${email} - Incorrect password.`);
                return res.status(401).json({ success: false, message: 'Invalid email or password' });
            }

            if (row.status === 'banned') {
                logger.warn(`Login attempt for banned account: ${email}`);
                return res.status(403).json({ 
                    success: false, 
                    message: 'Your account has been banned.',
                    banReason: row.ban_reason || 'No reason provided.'
                });
            }

            const tokens = generateTokens(row);
            res.cookie('accessToken', tokens.accessToken, {
                httpOnly: true,
                secure: config.NODE_ENV === 'production',
                sameSite: 'strict',
                maxAge: 360000000
            });
            
            logger.info(`User logged in: ${row.username} (${row.email}) from IP: ${req.ip}`);
            res.json({ 
                success: true, 
                message: 'Login successful', 
                accessToken: tokens.accessToken, 
                refreshToken: tokens.refreshToken,
                user: {
                    email: row.email,
                    username: row.username,
                    isAdmin: row.is_admin
                },
                redirect: '/home.html'
            });
        } catch (error) {
            logger.error(`Error during login for email ${email}: ${error.message}`);
            res.status(500).json({ success: false, message: 'Internal server error' });
        }
    });
}

const createAccountHandler = async (req, res) => {
    try {
        const { email, username, password, discordUsername, discordId, isAdmin } = req.body;
        
        if (!email || !username || !password) {
            logger.warn(`Failed account creation attempt by admin ${req.user ? req.user.email : 'N/A'} - Missing required fields.`);
            return res.status(400).json({ 
                success: false, 
                message: 'Email, username and password are required' 
            });
        }

        console.log('Full request body:', req.body);
        console.log('Received isAdmin value:', isAdmin);
        console.log('Type of received isAdmin:', typeof isAdmin);
        
        let isAdminValue;
        if (isAdmin === 1 || isAdmin === '1' || isAdmin === true) {
            isAdminValue = 1;
        } else {
            isAdminValue = 0;
        }
        
        console.log('Converted isAdmin value:', isAdminValue);
        console.log('Type of converted isAdmin:', typeof isAdminValue);
        
        const db = getDB();
        
        const hashedPassword = await bcrypt.hash(password, 10);
        
        const existingUser = await new Promise((resolve, reject) => {
            db.get('SELECT * FROM users WHERE email = ? OR username = ?', [email, username], (err, row) => {
                if (err) reject(err);
                else resolve(row);
            });
        });
        
        if (existingUser) {
            logger.warn(`Account creation attempt failed by admin ${req.user ? req.user.email : 'N/A'} - Email or username already exists: ${email || username}.`);
            return res.status(400).json({ 
                success: false, 
                message: existingUser.email === email ? 'Email already exists' : 'Username already exists' 
            });
        }
        
        const params = [email, username, hashedPassword, discordUsername, discordId, isAdminValue];
        console.log('Database parameters:', params);
        
        const result = await new Promise((resolve, reject) => {
            db.serialize(() => {
                db.run('BEGIN TRANSACTION');
                
                db.run(
                    'INSERT INTO users (email, username, password, discord_username, discord_id, is_admin) VALUES (?, ?, ?, ?, ?, ?)',
                    params,
                    function(err) {
                        if (err) {
                            db.run('ROLLBACK');
                            reject(err);
                            return;
                        }
                        
                        const userId = this.lastID;
                        
                        db.get('SELECT id, email, username, is_admin FROM users WHERE id = ?', [userId], (err, insertedUser) => {
                            if (err) {
                                db.run('ROLLBACK');
                                reject(err);
                                return;
                            }
                            
                            if (!insertedUser) {
                                db.run('ROLLBACK');
                                reject(new Error('User not found after insertion'));
                                return;
                            }
                            
                            console.log('Successfully inserted user:', insertedUser);
                            
                            if (insertedUser.is_admin !== isAdminValue) {
                                console.error('is_admin value mismatch:', {
                                    expected: isAdminValue,
                                    actual: insertedUser.is_admin
                                });
                                db.run('ROLLBACK');
                                reject(new Error('Admin status mismatch'));
                                return;
                            }
                            
                            db.run('COMMIT');
                            logger.info(`Account created by admin ${req.user ? req.user.email : 'N/A'}: Username: ${insertedUser.username}, Email: ${insertedUser.email}, Admin status: ${insertedUser.is_admin}`);
                            resolve(insertedUser);
                        });
                    }
                );
            });
        });
        
        res.json({ 
            success: true, 
            message: 'Account created successfully',
            user: {
                id: result.id,
                email: result.email,
                username: result.username,
                isAdmin: result.is_admin
            }
        });
    } catch (error) {
        logger.error(`Error creating account by admin ${req.user ? req.user.email : 'N/A'}: ${error.message}`);
        res.status(500).json({ 
            success: false, 
            message: error.message || 'Error creating account' 
        });
    }
};

function logoutHandler(req, res) {
    const token = req.headers.authorization?.split(' ')[1];
    if (token) {
        logger.info(`User logged out (token blacklisted).`);
        tokenBlacklist.add(token);
    }
    res.clearCookie('accessToken', {
        httpOnly: true,
        secure: config.NODE_ENV === 'production',
        sameSite: 'strict'
    });
    res.json({ success: true, message: 'Logged out successfully' });
}

module.exports = {
    loginHandler,
    createAccountHandler,
    logoutHandler
}; 