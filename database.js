const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('chat.db');

db.serialize(() => {
  // Enable foreign key constraints
  db.run(`PRAGMA foreign_keys = ON`);

  // Users
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password_hash TEXT,
    role TEXT DEFAULT 'user',
    invited_by INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(invited_by) REFERENCES users(id)
  )`);

  // Messages
  db.run(`CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id INTEGER NOT NULL,
    receiver_id INTEGER NOT NULL,
    message TEXT NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(sender_id) REFERENCES users(id),
                                               FOREIGN KEY(receiver_id) REFERENCES users(id)
  )`);

  // Invites
  db.run(`CREATE TABLE IF NOT EXISTS invites (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code TEXT UNIQUE,
    created_by INTEGER NOT NULL,
    used_by INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    used_at DATETIME,
    FOREIGN KEY(created_by) REFERENCES users(id),
                                              FOREIGN KEY(used_by) REFERENCES users(id)
  )`);

  // Conversations (track which users have a conversation + aes_key)
  db.run(`CREATE TABLE IF NOT EXISTS conversations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user1_id INTEGER NOT NULL,
    user2_id INTEGER NOT NULL,
    UNIQUE(user1_id, user2_id),
                                                    FOREIGN KEY(user1_id) REFERENCES users(id),
                                                    FOREIGN KEY(user2_id) REFERENCES users(id)
  )`);

  // Pending keys for offline users (AES keys stored temporarily)
  db.run(`CREATE TABLE IF NOT EXISTS pending_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    conversation_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    aes_key TEXT NOT NULL,
    delivered INTEGER DEFAULT 0,
    FOREIGN KEY(conversation_id) REFERENCES conversations(id),
                                                   FOREIGN KEY(user_id) REFERENCES users(id)
  )`);
});

// Add aes_key column to conversations table if it doesn't exist
db.all(`PRAGMA table_info(conversations)`, (err, rows) => {
  if (err) return console.error(err);
  const hasAesKey = rows.some(r => r.name === "aes_key");
  if (!hasAesKey) {
    db.run(`ALTER TABLE conversations ADD COLUMN aes_key TEXT`, (err2) => {
      if (err2) console.error("Failed to add aes_key column:", err2);
      else console.log("Added aes_key column to conversations table");
    });
  }
});

// Add last_seen_msg_id column to users table if it doesn't exist
// Add profile_picture column to users table if it doesn't exist
db.all(`PRAGMA table_info(users)`, (err, rows) => {
  if (err) return console.error(err);

  const hasLastSeen = rows.some(r => r.name === "last_seen_msg_id");
  if (!hasLastSeen) {
    db.run(`ALTER TABLE users ADD COLUMN last_seen_msg_id INTEGER DEFAULT 0`, (err2) => {
      if (err2) console.error("Failed to add last_seen_msg_id column:", err2);
      else console.log("Added last_seen_msg_id column to users table");
    });
  }

  const hasProfilePic = rows.some(r => r.name === "profile_picture");
  if (!hasProfilePic) {
    db.run(`ALTER TABLE users ADD COLUMN profile_picture TEXT`, (err2) => {
      if (err2) console.error("Failed to add profile_picture column:", err2);
      else console.log("Added profile_picture column to users table");
    });
  }
});

// --- Ensure specific users always have the 'tester' role on startup ---

const testerList = `
- tomiszivacs
`;

// Parse the list (strip dashes, trim whitespace)
const testerUsernames = testerList
.split('\n')
.map(line => line.replace(/^-/, '').trim())
.filter(Boolean);

testerUsernames.forEach(username => {
  db.run(
    `UPDATE users SET role = 'tester' WHERE username = ?`,
    [username],
    function (err) {
      if (err) console.error(``, err);
      else if (this.changes > 0)
        console.log(``);
      else
        console.log(``);
    }
  );
});


module.exports = db;
