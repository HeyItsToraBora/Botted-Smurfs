const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('crypto.db');

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS coins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    symbol TEXT UNIQUE NOT NULL
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS networks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    coin_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    address TEXT NOT NULL,
    FOREIGN KEY (coin_id) REFERENCES coins(id) ON DELETE CASCADE
  )`);
});

// CRUD functions
const addCoin = (name, symbol, cb) => db.run('INSERT INTO coins (name, symbol) VALUES (?, ?)', [name, symbol], cb);
const removeCoin = (symbol, cb) => db.run('DELETE FROM coins WHERE symbol = ?', [symbol], cb);
const getCoins = (cb) => db.all('SELECT * FROM coins', cb);
const addNetwork = (coinSymbol, networkName, address, cb) => {
  db.get('SELECT id FROM coins WHERE symbol = ?', [coinSymbol], (err, row) => {
    if (err || !row) return cb(err || new Error('Coin not found'));
    db.run('INSERT INTO networks (coin_id, name, address) VALUES (?, ?, ?)', [row.id, networkName, address], cb);
  });
};
const removeNetwork = (networkId, cb) => db.run('DELETE FROM networks WHERE id = ?', [networkId], cb);
const getNetworks = (coinSymbol, cb) => {
  db.get('SELECT id FROM coins WHERE symbol = ?', [coinSymbol], (err, row) => {
    if (err || !row) return cb(err || new Error('Coin not found'));
    db.all('SELECT * FROM networks WHERE coin_id = ?', [row.id], cb);
  });
};
const getAllNetworks = (cb) => db.all('SELECT networks.*, coins.symbol as coin_symbol FROM networks JOIN coins ON networks.coin_id = coins.id', cb);
const updateAddress = (networkId, newAddress, cb) => db.run('UPDATE networks SET address = ? WHERE id = ?', [newAddress, networkId], cb);

module.exports = {
  addCoin,
  removeCoin,
  getCoins,
  addNetwork,
  removeNetwork,
  getNetworks,
  getAllNetworks,
  updateAddress,
  db
}; 