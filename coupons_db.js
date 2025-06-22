const sqlite3 = require('sqlite3').verbose();
const fs = require('fs');
const path = require('path');
const config = require('./config');
const logger = require('./utils/logger');

const couponsDbPath = config.COUPONS_DB_PATH;
let couponsDb;

function initCouponsDB() {
    return new Promise((resolve, reject) => {
        if (!fs.existsSync(couponsDbPath)) {
            couponsDb = new sqlite3.Database(couponsDbPath, (err) => {
                if (err) {
                    logger.error('Error creating coupons database:', err);
                    reject(err);
                    return;
                }
                const createCouponsTable = `
                CREATE TABLE coupons (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    discord_id TEXT,
                    discord_name TEXT,
                    coupon_id TEXT UNIQUE NOT NULL,
                    percentage_per_purchase REAL NOT NULL,
                    max_usage INTEGER DEFAULT 999,
                    times_used INTEGER DEFAULT 0,
                    total_discount_amount REAL DEFAULT 0,
                    last_used_at TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );`;

                couponsDb.run(createCouponsTable, (err) => {
                    if (err) {
                        logger.error('Error creating coupons table:', err);
                        reject(err);
                        return;
                    }
                    logger.info('Coupons table created successfully in coupons.db');
                    resolve();
                });
            });
        } else {
            couponsDb = new sqlite3.Database(couponsDbPath, (err) => {
                if (err) {
                    logger.error('Error opening coupons database:', err);
                    reject(err);
                    return;
                }
                
                // Check if new columns exist and add them if they don't
                couponsDb.all("PRAGMA table_info(coupons)", (err, columns) => {
                    if (!err) {
                        const columnNames = columns.map(col => col.name);
                        
                        if (!columnNames.includes('times_used')) {
                            couponsDb.run("ALTER TABLE coupons ADD COLUMN times_used INTEGER DEFAULT 0", (err) => {
                                if (err) {
                                    logger.error('Error adding times_used column:', err);
                                } else {
                                    logger.info('Added times_used column to coupons table');
                                }
                            });
                        }
                        
                        if (!columnNames.includes('total_discount_amount')) {
                            couponsDb.run("ALTER TABLE coupons ADD COLUMN total_discount_amount REAL DEFAULT 0", (err) => {
                                if (err) {
                                    logger.error('Error adding total_discount_amount column:', err);
                                } else {
                                    logger.info('Added total_discount_amount column to coupons table');
                                }
                            });
                        }
                        
                        if (!columnNames.includes('last_used_at')) {
                            couponsDb.run("ALTER TABLE coupons ADD COLUMN last_used_at TIMESTAMP", (err) => {
                                if (err) {
                                    logger.error('Error adding last_used_at column:', err);
                                } else {
                                    logger.info('Added last_used_at column to coupons table');
                                }
                            });
                        }
                        
                        if (!columnNames.includes('max_usage')) {
                            couponsDb.run("ALTER TABLE coupons ADD COLUMN max_usage INTEGER DEFAULT 999", (err) => {
                                if (err) {
                                    logger.error('Error adding max_usage column:', err);
                                } else {
                                    logger.info('Added max_usage column to coupons table');
                                }
                            });
                        }
                    }
                });
                
                resolve();
            });
        }
    });
}

function getCouponsDB() {
    return couponsDb;
}

// Function to update coupon usage statistics
function updateCouponUsage(couponId, discountAmount) {
    return new Promise((resolve, reject) => {
        couponsDb.run(
            'UPDATE coupons SET times_used = times_used + 1, total_discount_amount = total_discount_amount + ?, last_used_at = CURRENT_TIMESTAMP, max_usage = max_usage - 1 WHERE id = ?',
            [discountAmount, couponId],
            function(err) {
                if (err) {
                    logger.error('Error updating coupon usage:', err);
                    reject(err);
                    return;
                }
                resolve(this.changes > 0);
            }
        );
    });
}

module.exports = {
    initCouponsDB,
    getCouponsDB,
    updateCouponUsage
}; 