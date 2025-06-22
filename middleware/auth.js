const jwt = require('jsonwebtoken');
const config = require('../config');
const logger = require('../utils/logger');
const { getDB } = require('../db');

// Token blacklist (in production, use Redis or similar)
const tokenBlacklist = new Set();

function AdminOnly(handler) {
    return (req, res, next) => {
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

            // Check if token is blacklisted
            if (tokenBlacklist.has(token)) {
                return res.status(401).json({ 
                    success: false, 
                    message: 'Token has been invalidated' 
                });
            }

            const decoded = jwt.verify(token, config.JWT_SECRET);
            
            // Check if user exists and is admin
            const db = getDB();
            db.get('SELECT is_admin FROM users WHERE email = ?', [decoded.email], (err, row) => {
                if (err) {
                    logger.error('Database error:', err);
                    return res.status(500).json({ 
                        success: false, 
                        message: 'Database error' 
                    });
                }

                if (!row || !row.is_admin) {
                    return res.status(403).json({ 
                        success: false, 
                        message: 'Admin access required' 
                    });
                }

                req.user = decoded;
                // Call the handler function
                if (typeof handler === 'function') {
                    handler(req, res, next);
                } else {
                    logger.error('Handler is not a function:', handler);
                    return res.status(500).json({ 
                        success: false, 
                        message: 'Server configuration error' 
                    });
                }
            });
        } catch (error) {
            logger.error('Authentication error:', error);
            return res.status(401).json({ 
                success: false, 
                message: 'Invalid token' 
            });
        }
    };
}

// Generate access and refresh tokens
function generateTokens(user) {
    const accessToken = jwt.sign(
        { id: user.id, email: user.email },
        config.JWT_SECRET,
        { expiresIn: config.JWT_EXPIRES_IN }
    );

    const refreshToken = jwt.sign(
        { id: user.id, email: user.email },
        config.JWT_REFRESH_SECRET,
        { expiresIn: config.JWT_REFRESH_EXPIRES_IN }
    );

    // Clear any old tokens for this user from the blacklist
    for (const token of tokenBlacklist) {
        try {
            const decoded = jwt.verify(token, config.JWT_SECRET);
            if (decoded.email === user.email) {
                tokenBlacklist.delete(token);
            }
        } catch (error) {
            // If token is invalid, remove it from blacklist
            tokenBlacklist.delete(token);
        }
    }

    return { accessToken, refreshToken };
}

// Refresh token endpoint handler
async function refreshToken(req, res) {
    const { refreshToken } = req.body;

    if (!refreshToken) {
        return res.status(400).json({
            success: false,
            message: 'Refresh token is required'
        });
    }

    try {
        const decoded = jwt.verify(refreshToken, config.JWT_REFRESH_SECRET);
        const db = getDB();

        db.get('SELECT * FROM users WHERE email = ?', [decoded.email], (err, user) => {
            if (err) {
                logger.error('Database error:', err);
                return res.status(500).json({
                    success: false,
                    message: 'Database error'
                });
            }

            if (!user) {
                return res.status(404).json({
                    success: false,
                    message: 'User not found'
                });
            }

            const tokens = generateTokens(user);
            // Set the new access token cookie
            res.cookie('accessToken', tokens.accessToken, {
                httpOnly: true,
                secure: config.NODE_ENV === 'production',
                sameSite: 'strict'
            });
            res.json({
                success: true,
                ...tokens
            });
        });
    } catch (error) {
        logger.error('Token refresh error:', error);
        return res.status(401).json({
            success: false,
            message: 'Invalid refresh token'
        });
    }
}

// Logout handler
function logout(req, res) {
    const token = req.headers.authorization?.split(' ')[1];
    if (token) {
        tokenBlacklist.add(token);
    }
    // Clear the access token cookie
    res.clearCookie('accessToken', {
        httpOnly: true,
        secure: config.NODE_ENV === 'production',
        sameSite: 'strict'
    });
    res.json({ success: true, message: 'Logged out successfully' });
}

module.exports = {
    AdminOnly,
    generateTokens,
    refreshToken,
    logout
}; 