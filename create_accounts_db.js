const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');

const db = new sqlite3.Database('sqlite.db');

db.serialize(() => {
  db.run(`DROP TABLE IF EXISTS users`);
  db.run(`CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    is_admin BOOLEAN DEFAULT 0,
    status TEXT DEFAULT 'active',
    ban_reason TEXT,
    discord_id TEXT,
    discord_username TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )`);

  bcrypt.hash('test1234', 10, (err, hash) => {
    if (err) throw err;
    db.run(
      `INSERT INTO users (email, password, is_admin) VALUES (?, ?, ?)`,
      ['testuser@example.com', hash, 0],
      function (err) {
        if (err) throw err;
        console.log('Example user created!');
        db.close();
      }
    );
  });
}); 