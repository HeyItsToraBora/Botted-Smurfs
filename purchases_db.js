const sqlite3 = require('sqlite3').verbose();
const fs = require('fs');
const path = require('path');
const logger = require('./utils/logger');

const dbPath = 'purchases.db';
let db;

function initPurchasesDB() {
    return new Promise((resolve, reject) => {
        const exists = fs.existsSync(dbPath);
        db = new sqlite3.Database(dbPath, (err) => {
            if (err) {
                logger.error('Error opening purchases database:', err);
                reject(err);
                return;
            }
            if (!exists) {
                db.run(`CREATE TABLE IF NOT EXISTS purchases (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    user_email TEXT NOT NULL,
                    items TEXT NOT NULL,
                    payment_currency TEXT NOT NULL,
                    payment_networks TEXT NOT NULL,
                    total_before_coupon REAL NOT NULL,
                    coupon_code TEXT,
                    coupon_percent REAL,
                    subtotal_after_coupon REAL NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending',
                    payment_confirmation TEXT NOT NULL DEFAULT 'unconfirmed',
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )`, (err) => {
                    if (err) {
                        logger.error('Error creating purchases table:', err);
                        reject(err);
                    } else {
                        logger.info('Purchases table created');
                        resolve();
                    }
                });
            } else {
                // Try to add payment_confirmation column if it doesn't exist
                db.all("PRAGMA table_info(purchases)", (err, columns) => {
                    if (!err && Array.isArray(columns)) {
                        if (!columns.some(col => col.name === 'payment_confirmation')) {
                            db.run("ALTER TABLE purchases ADD COLUMN payment_confirmation TEXT NOT NULL DEFAULT 'unconfirmed'", (err) => {
                                if (err) logger.error('Error adding payment_confirmation column:', err);
                            });
                        }
                        // Add gmail_to_be_sent column if it doesn't exist
                        if (!columns.some(col => col.name === 'gmail_to_be_sent')) {
                            db.run("ALTER TABLE purchases ADD COLUMN gmail_to_be_sent TEXT", (err) => {
                                if (err) logger.error('Error adding gmail_to_be_sent column:', err);
                            });
                        }
                    }
                });
                resolve();
            }
        });
    });
}

function getPurchasesDB() {
    return db;
}

async function createPurchase(purchase) {
    return new Promise((resolve, reject) => {
        const {
            user_id,
            user_email,
            items,
            payment_currency,
            payment_networks,
            total_before_coupon,
            coupon_code,
            coupon_percent,
            subtotal_after_coupon,
            status = 'pending',
            payment_confirmation = 'unconfirmed',
            gmail_to_be_sent = null
        } = purchase;
        db.run(
            `INSERT INTO purchases (user_id, user_email, items, payment_currency, payment_networks, total_before_coupon, coupon_code, coupon_percent, subtotal_after_coupon, status, payment_confirmation, gmail_to_be_sent) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [user_id, user_email, JSON.stringify(items), payment_currency, payment_networks, total_before_coupon, coupon_code, coupon_percent, subtotal_after_coupon, status, payment_confirmation, gmail_to_be_sent],
            function(err) {
                if (err) {
                    logger.error('Error creating purchase:', err);
                    reject(err);
                } else {
                    resolve(this.lastID);
                }
            }
        );
    });
}

async function getPurchaseById(id) {
    return new Promise((resolve, reject) => {
        db.get('SELECT * FROM purchases WHERE id = ?', [id], (err, row) => {
            if (err) return reject(err);
            if (row) {
                row.items = JSON.parse(row.items);
                row.payment_networks = JSON.parse(row.payment_networks);
            }
            resolve(row);
        });
    });
}

async function updatePurchaseStatus(id, status) {
    return new Promise((resolve, reject) => {
        db.run('UPDATE purchases SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?', [status, id], function(err) {
            if (err) return reject(err);
            resolve(this.changes > 0);
        });
    });
}

async function updatePaymentConfirmation(id, payment_confirmation) {
    return new Promise((resolve, reject) => {
        db.run('UPDATE purchases SET payment_confirmation = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?', [payment_confirmation, id], function(err) {
            if (err) return reject(err);
            resolve(this.changes > 0);
        });
    });
}

module.exports = {
    initPurchasesDB,
    getPurchasesDB,
    createPurchase,
    getPurchaseById,
    updatePurchaseStatus,
    updatePaymentConfirmation
}; 