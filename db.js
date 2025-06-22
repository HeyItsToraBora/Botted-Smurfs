const sqlite3 = require('sqlite3').verbose();
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcrypt');
const config = require('./config');
const logger = require('./utils/logger');

const dbPath = config.DB_PATH;
let db;

function initDB() {
    return new Promise((resolve, reject) => {
        // Check if database exists
        if (!fs.existsSync(dbPath)) {
            db = new sqlite3.Database(dbPath, (err) => {
                if (err) {
                    logger.error('Error creating database:', err);
                    reject(err);
                    return;
                }

                // Create users table
                const createTable = `
                CREATE TABLE users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT UNIQUE NOT NULL,
                    username TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    status TEXT DEFAULT 'active',
                    ban_reason TEXT,
                    is_admin BOOLEAN DEFAULT 0,
                    discord_id TEXT,
                    discord_username TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );`;

                db.run(createTable, (err) => {
                    if (err) {
                        logger.error('Error creating users table:', err);
                        reject(err);
                        return;
                    }
                    logger.info('Users table created successfully');
                    
                    // Create default admin account
                    const adminEmail = 'admin@example.com';
                    const adminUsername = 'admin';
                    const adminPassword = 'Admin@123'; // This is a secure password with uppercase, number, and special char
                    
                    bcrypt.hash(adminPassword, 10, (err, hashedPassword) => {
                        if (err) {
                            logger.error('Error hashing password:', err);
                            reject(err);
                            return;
                        }

                        db.run(
                            'INSERT INTO users (email, username, password, is_admin, created_at) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)',
                            [adminEmail, adminUsername, hashedPassword, 1],
                            (err) => {
                                if (err) {
                                    logger.error('Error creating admin user:', err);
                                    reject(err);
                                    return;
                                }
                                logger.info('Default admin account created successfully');
                                resolve();
                            }
                        );
                    });
                });
            });
        } else {
            db = new sqlite3.Database(dbPath, (err) => {
                if (err) {
                    logger.error('Error opening database:', err);
                    reject(err);
                    return;
                }
                resolve();
            });
        }
    });
}

function getDB() {
    return db;
}

module.exports = {
    initDB,
    getDB
}; 