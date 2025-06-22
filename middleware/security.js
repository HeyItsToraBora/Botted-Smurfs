const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const { body, validationResult } = require('express-validator');
const config = require('../config');
const logger = require('../utils/logger');

// Rate limiting middleware
const limiter = rateLimit({
    windowMs: config.RATE_LIMIT_WINDOW_MS,
    max: config.RATE_LIMIT_MAX,
    message: 'Too many requests from this IP, please try again later.',
    handler: (req, res) => {
        logger.warn(`Rate limit exceeded for IP: ${req.ip}`);
        res.status(429).json({
            success: false,
            message: 'Too many requests from this IP, please try again later.'
        });
    }
});

// Input validation middleware
const validateLogin = [
    body('email').isEmail().normalizeEmail(),
    body('password').isLength({ min: 1 }),
    (req, res, next) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            console.log('Validation errors:', errors.array());
            return res.status(400).json({ 
                success: false, 
                errors: errors.array() 
            });
        }
        console.log('Login validation passed');
        next();
    }
];

const validateCreateAccount = [
    body('email').isEmail().normalizeEmail(),
    body('username').isLength({ min: 3 }).trim().escape(),
    body('password').isLength({ min: 1 }),
    body('discordUsername').optional().trim().escape(),
    body('discordId').optional().trim().escape(),
    body('isAdmin').optional().isBoolean(),
    async (req, res, next) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({ 
                    success: false, 
                    errors: errors.array() 
                });
            }
            next();
        } catch (error) {
            next(error);
        }
    }
];

// Error handling middleware
const errorHandler = (err, req, res, next) => {
    logger.error(err.stack);
    res.status(err.status || 500).json({
        success: false,
        message: config.NODE_ENV === 'production' 
            ? 'Internal server error' 
            : err.message
    });
};

// Security headers middleware
const securityHeaders = helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: ["'self'"]
        }
    },
    crossOriginEmbedderPolicy: true,
    crossOriginOpenerPolicy: true,
    crossOriginResourcePolicy: { policy: "same-site" },
    dnsPrefetchControl: true,
    frameguard: { action: "deny" },
    hidePoweredBy: true,
    hsts: true,
    ieNoOpen: true,
    noSniff: true,
    referrerPolicy: { policy: "strict-origin-when-cross-origin" },
    xssFilter: true
});

module.exports = {
    limiter,
    validateLogin,
    validateCreateAccount,
    errorHandler,
    securityHeaders
}; 