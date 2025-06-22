const sqlite3 = require('sqlite3').verbose();
const fs = require('fs');
const path = require('path');
const logger = require('./utils/logger');

const cartDbPath = 'cart.db';
let cartDb;

function initCartDB() {
    return new Promise((resolve, reject) => {
        const exists = fs.existsSync(cartDbPath);
        cartDb = new sqlite3.Database(cartDbPath, (err) => {
            if (err) {
                logger.error('Error opening cart database:', err);
                reject(err);
                return;
            }
            if (!exists) {
                // Create tables
                cartDb.serialize(() => {
                    cartDb.run(`CREATE TABLE IF NOT EXISTS carts (
                        cart_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER NOT NULL,
                        user_email TEXT NOT NULL,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                    )`);
                    cartDb.run(`CREATE TABLE IF NOT EXISTS cart_items (
                        item_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        cart_id INTEGER NOT NULL,
                        offer_id INTEGER NOT NULL,
                        offer_type TEXT NOT NULL,
                        offer_name TEXT NOT NULL,
                        server_name TEXT NOT NULL,
                        quantity INTEGER NOT NULL,
                        price_per_account REAL NOT NULL,
                        total_price REAL NOT NULL,
                        gmail_to_be_sent TEXT,
                        applied_coupon_id INTEGER,
                        coupon_discount_amount REAL DEFAULT 0,
                        subtotal_before_coupon REAL,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY(cart_id) REFERENCES carts(cart_id)
                    )`);
                });
            } else {
                // Check if user_email column exists, if not add it
                cartDb.get("PRAGMA table_info(carts)", (err, rows) => {
                    if (!err) {
                        cartDb.all("PRAGMA table_info(carts)", (err, columns) => {
                            if (!err) {
                                const hasEmailColumn = columns.some(col => col.name === 'user_email');
                                if (!hasEmailColumn) {
                                    cartDb.run("ALTER TABLE carts ADD COLUMN user_email TEXT", (err) => {
                                        if (err) {
                                            logger.error('Error adding user_email column:', err);
                                        } else {
                                            logger.info('Added user_email column to carts table');
                                        }
                                    });
                                }
                            }
                        });
                    }
                });
                
                // Check if coupon columns exist in cart_items, if not add them
                cartDb.all("PRAGMA table_info(cart_items)", (err, columns) => {
                    if (!err) {
                        const columnNames = columns.map(col => col.name);
                        
                        if (!columnNames.includes('applied_coupon_id')) {
                            cartDb.run("ALTER TABLE cart_items ADD COLUMN applied_coupon_id INTEGER", (err) => {
                                if (err) {
                                    logger.error('Error adding applied_coupon_id column:', err);
                                } else {
                                    logger.info('Added applied_coupon_id column to cart_items table');
                                }
                            });
                        }
                        
                        if (!columnNames.includes('coupon_discount_amount')) {
                            cartDb.run("ALTER TABLE cart_items ADD COLUMN coupon_discount_amount REAL DEFAULT 0", (err) => {
                                if (err) {
                                    logger.error('Error adding coupon_discount_amount column:', err);
                                } else {
                                    logger.info('Added coupon_discount_amount column to cart_items table');
                                }
                            });
                        }
                        
                        if (!columnNames.includes('subtotal_before_coupon')) {
                            cartDb.run("ALTER TABLE cart_items ADD COLUMN subtotal_before_coupon REAL", (err) => {
                                if (err) {
                                    logger.error('Error adding subtotal_before_coupon column:', err);
                                } else {
                                    logger.info('Added subtotal_before_coupon column to cart_items table');
                                }
                            });
                        }
                    }
                });
            }
            resolve();
        });
    });
}

function getCartDB() {
    return cartDb;
}

async function getOrCreateCart(userId) {
    return new Promise((resolve, reject) => {
        // First get the user's email from the users table
        const { getDB } = require('./db');
        const userDb = getDB();
        
        userDb.get('SELECT email FROM users WHERE id = ?', [userId], (err, user) => {
            if (err) return reject(err);
            if (!user) return reject(new Error('User not found'));
            
            const userEmail = user.email;
            
            // Now check if cart exists
            cartDb.get('SELECT * FROM carts WHERE user_id = ?', [userId], (err, cart) => {
                if (err) return reject(err);
                if (cart) return resolve(cart);
                
                // Create new cart with user's email
                cartDb.run('INSERT INTO carts (user_id, user_email) VALUES (?, ?)', [userId, userEmail], function(err) {
                    if (err) return reject(err);
                    resolve({ cart_id: this.lastID, user_id: userId, user_email: userEmail });
                });
            });
        });
    });
}

async function getCart(userId) {
    return new Promise((resolve, reject) => {
        cartDb.get('SELECT cart_id FROM carts WHERE user_id = ?', [userId], (err, cart) => {
            if (err) return reject(err);
            if (!cart) return resolve(null);
            cartDb.all(`SELECT * FROM cart_items WHERE cart_id = ? ORDER BY created_at DESC`, [cart.cart_id], (err, items) => {
                if (err) return reject(err);
                resolve({ cart_id: cart.cart_id, items: items || [] });
            });
        });
    });
}

async function addItemToCart(cartId, offerData) {
    return new Promise((resolve, reject) => {
        const {
            offerId,
            offerType = 'default',
            offerName,
            serverName,
            quantity,
            pricePerAccount,
            gmailToBeSent
        } = offerData;
        const insertQuery = `INSERT INTO cart_items (
            cart_id, offer_id, offer_type, offer_name, server_name, quantity, price_per_account, total_price, gmail_to_be_sent
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`;
        const totalPrice = quantity * pricePerAccount;
        const params = [cartId, offerId, offerType, offerName, serverName, quantity, pricePerAccount, totalPrice, gmailToBeSent];
        cartDb.run(insertQuery, params, function(err) {
            if (err) {
                logger.error('Error adding item to cart:', err);
                reject(err);
                return;
            }
            resolve(this.lastID);
        });
    });
}

async function removeItemFromCart(itemId, userId) {
    return new Promise((resolve, reject) => {
        cartDb.run(`DELETE FROM cart_items WHERE item_id = ? AND cart_id IN (SELECT cart_id FROM carts WHERE user_id = ?)`, [itemId, userId], function(err) {
            if (err) return reject(err);
            resolve(this.changes > 0);
        });
    });
}

async function clearCart(userId) {
    return new Promise((resolve, reject) => {
        cartDb.run(`DELETE FROM cart_items WHERE cart_id IN (SELECT cart_id FROM carts WHERE user_id = ?)`, [userId], function(err) {
            if (err) return reject(err);
            resolve(this.changes);
        });
    });
}

async function updateItemQuantity(itemId, quantity, userId) {
    return new Promise((resolve, reject) => {
        cartDb.run(`UPDATE cart_items SET quantity = ?, total_price = price_per_account * ? WHERE item_id = ? AND cart_id IN (SELECT cart_id FROM carts WHERE user_id = ?)`, [quantity, quantity, itemId, userId], function(err) {
            if (err) return reject(err);
            resolve(this.changes > 0);
        });
    });
}

async function getCartTotal(userId) {
    return new Promise((resolve, reject) => {
        cartDb.get(`SELECT SUM(total_price) as total FROM cart_items WHERE cart_id IN (SELECT cart_id FROM carts WHERE user_id = ?)`, [userId], (err, result) => {
            if (err) return reject(err);
            resolve(result ? result.total || 0 : 0);
        });
    });
}

// Function to apply coupon to cart
async function applyCouponToCart(userId, couponId, discountAmount) {
    return new Promise((resolve, reject) => {
        // First, get the cart total before coupon
        cartDb.get(`SELECT SUM(total_price) as subtotal FROM cart_items WHERE cart_id IN (SELECT cart_id FROM carts WHERE user_id = ?)`, [userId], (err, result) => {
            if (err) return reject(err);
            
            const subtotal = result ? result.subtotal || 0 : 0;
            
            // Update all cart items with coupon information
            cartDb.run(`UPDATE cart_items SET 
                applied_coupon_id = ?, 
                coupon_discount_amount = ?, 
                subtotal_before_coupon = ? 
                WHERE cart_id IN (SELECT cart_id FROM carts WHERE user_id = ?)`, 
                [couponId, discountAmount, subtotal, userId], function(err) {
                if (err) return reject(err);
                resolve(this.changes > 0);
            });
        });
    });
}

// Function to remove coupon from cart
async function removeCouponFromCart(userId) {
    return new Promise((resolve, reject) => {
        cartDb.run(`UPDATE cart_items SET 
            applied_coupon_id = NULL, 
            coupon_discount_amount = 0, 
            subtotal_before_coupon = NULL 
            WHERE cart_id IN (SELECT cart_id FROM carts WHERE user_id = ?)`, 
            [userId], function(err) {
            if (err) return reject(err);
            // Return true if the operation was successful, regardless of whether rows were updated
            resolve(true);
        });
    });
}

// Function to get applied coupon info
async function getAppliedCoupon(userId) {
    return new Promise((resolve, reject) => {
        cartDb.get(`SELECT applied_coupon_id, coupon_discount_amount, subtotal_before_coupon 
                    FROM cart_items 
                    WHERE cart_id IN (SELECT cart_id FROM carts WHERE user_id = ?) 
                    AND applied_coupon_id IS NOT NULL 
                    LIMIT 1`, [userId], (err, result) => {
            if (err) return reject(err);
            resolve(result);
        });
    });
}

// Function to update gmail for all cart items
async function updateCartGmail(userId, gmail) {
    return new Promise((resolve, reject) => {
        cartDb.run(`UPDATE cart_items SET gmail_to_be_sent = ? 
                    WHERE cart_id IN (SELECT cart_id FROM carts WHERE user_id = ?)`, 
                    [gmail, userId], function(err) {
            if (err) return reject(err);
            resolve(this.changes > 0);
        });
    });
}

module.exports = {
    initCartDB,
    getCartDB,
    getOrCreateCart,
    getCart,
    addItemToCart,
    removeItemFromCart,
    clearCart,
    updateItemQuantity,
    getCartTotal,
    applyCouponToCart,
    removeCouponFromCart,
    getAppliedCoupon,
    updateCartGmail
}; 