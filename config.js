require('dotenv').config();

module.exports = {
    // Server Configuration
    PORT: process.env.PORT || 8080,
    NODE_ENV: process.env.NODE_ENV || 'development',
    
    // Security
    JWT_SECRET: process.env.JWT_SECRET || 'your-secret-key',
    JWT_REFRESH_SECRET: process.env.JWT_REFRESH_SECRET || 'your-refresh-secret-key',
    JWT_EXPIRES_IN: '1h',
    JWT_REFRESH_EXPIRES_IN: '7d',
    
    // Rate Limiting
    RATE_LIMIT_WINDOW_MS: 15 * 60 * 1000, // 15 minutes
    RATE_LIMIT_MAX: 100, // limit each IP to 100 requests per windowMs
    
    // Database
    DB_PATH: process.env.DB_PATH || 'sqlite.db',
    OFFERS_DB_PATH: process.env.OFFERS_DB_PATH || 'offers.db',
    COUPONS_DB_PATH: process.env.COUPONS_DB_PATH || 'coupons.db',
    
    // Session
    SESSION_SECRET: process.env.SESSION_SECRET || 'your-session-secret',
    SESSION_MAX_AGE: 24 * 60 * 60 * 1000, // 24 hours
    
    // Account Security
    MAX_LOGIN_ATTEMPTS: 5,
    LOCKOUT_TIME: 15 * 60 * 1000, // 15 minutes
    
    // CORS
    CORS_ORIGIN: process.env.CORS_ORIGIN || '*',
    
    // Logging
    LOG_LEVEL: process.env.LOG_LEVEL || 'info',

    // Discord Webhook for Logging
    DISCORD_WEBHOOK_URL: process.env.DISCORD_WEBHOOK_URL || 'https://discord.com/api/webhooks/1384135572511264899/ZA9_nmOmaWFcwkU51Js5gl2TP-YyhvL2gIBgrywW07pDUh5kW5iIdc7HPifEC1vz-Ij0', // Your Discord Webhook URL
}; 