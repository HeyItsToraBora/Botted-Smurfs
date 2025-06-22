const sqlite3 = require('sqlite3').verbose();
const fs = require('fs');
const path = require('path');
const config = require('./config');
const logger = require('./utils/logger');

const offersDbPath = config.OFFERS_DB_PATH;
let offersDb;

function initOffersDB() {
    return new Promise((resolve, reject) => {
        // Always connect to the database file.
        offersDb = new sqlite3.Database(offersDbPath, (err) => {
            if (err) {
                logger.error('Error opening or creating offers database:', err);
                return reject(err);
            }
            logger.info('Successfully connected to the offers database.');

            const createOffersTable = `
            CREATE TABLE IF NOT EXISTS offers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                header TEXT NOT NULL,
                description TEXT NOT NULL,
                details TEXT,
                offer_type TEXT NOT NULL,
                min_quantity INTEGER NOT NULL,
                available_servers TEXT,
                img_url TEXT,
                price_per_acc REAL NOT NULL,
                available_quantity INTEGER NOT NULL DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );`;

            offersDb.run(createOffersTable, (err) => {
                if (err) {
                    logger.error('Error creating offers table:', err);
                    return reject(err);
                }
                logger.info('Offers table checked/created successfully.');
                
                // Now, safely check and add columns
                checkAndAddColumns(resolve, reject);
            });
        });
    });
}

function checkAndAddColumns(resolve, reject) {
    offersDb.all("PRAGMA table_info(offers)", (err, rows) => {
        if (err) {
            logger.error('Error checking offers table info:', err);
            return reject(err);
        }

        const columns = new Set(rows.map(row => row.name));
        const columnsToAdd = [];

        if (!columns.has('available_quantity')) {
            columnsToAdd.push("ALTER TABLE offers ADD COLUMN available_quantity INTEGER NOT NULL DEFAULT 0");
        }
        if (!columns.has('offer_type')) {
            columnsToAdd.push("ALTER TABLE offers ADD COLUMN offer_type TEXT NOT NULL DEFAULT 'default'");
        }

        if (columnsToAdd.length === 0) {
            logger.info('All required columns already exist in offers table.');
            return resolve();
        }

        let completed = 0;
        columnsToAdd.forEach(sql => {
            offersDb.run(sql, (err) => {
                completed++;
                if (err) {
                    logger.error(`Error adding column with SQL: ${sql}`, err);
                    // Decide if you want to reject on first error or continue
                } else {
                    logger.info(`Successfully executed: ${sql}`);
                }
                
                if (completed === columnsToAdd.length) {
                    resolve();
                }
            });
        });
    });
}

function getOffersDB() {
    return offersDb;
}

module.exports = {
    initOffersDB,
    getOffersDB
}; 