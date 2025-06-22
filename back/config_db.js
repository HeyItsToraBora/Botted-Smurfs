const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('config.db');

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS config (
    key TEXT PRIMARY KEY,
    value TEXT
  )`);
  // Ensure min_order_price exists
  db.get('SELECT value FROM config WHERE key = ?', ['min_order_price'], (err, row) => {
    if (!row) db.run('INSERT INTO config (key, value) VALUES (?, ?)', ['min_order_price', '0']);
  });
});

function getMinOrderPrice(cb) {
  db.get('SELECT value FROM config WHERE key = ?', ['min_order_price'], (err, row) => {
    if (err) return cb(err);
    cb(null, row ? parseFloat(row.value) : 0);
  });
}

function setMinOrderPrice(value, cb) {
  db.run('REPLACE INTO config (key, value) VALUES (?, ?)', ['min_order_price', String(value)], cb);
}

module.exports = { getMinOrderPrice, setMinOrderPrice, db }; 