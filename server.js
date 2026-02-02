const sharp = require('sharp'); 
const { Buffer } = require('buffer');
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const db = require('./database'); 
const app = express();
const path = require('path');

require('dotenv').config();

// Serve static files
app.use(express.static(path.join(__dirname, 'public')));

const SECRET_KEY = process.env.SECRET_KEY;
if (!SECRET_KEY) throw new Error("Missing SECRET_KEY in environment variables");

//app.use(express.json());


const CLEANUP_INTERVAL_MS = 60 * 1000; // run cleanup every 60 seconds

function cleanupStore(store, windowMs) {
    const now = Date.now();
    for (const key in store) {
        const entry = store[key];
        if (entry.timestamps) {
            entry.timestamps = entry.timestamps.filter(ts => now - ts < windowMs);
        }

        if ((!entry.timestamps || entry.timestamps.length === 0) && (!entry.blockedUntil || entry.blockedUntil < now)) {
            delete store[key];
        }
    }
}

setInterval(() => {
    cleanupStore(userMessageTimestamps, rateLimitWindowMs);
    cleanupStore(loginAttemptsByIP, LOGIN_WINDOW_MS);
    cleanupStore(loginAttemptsByUser, LOGIN_WINDOW_MS);
    cleanupStore(inviteAttemptTimestamps, WINDOW_MS);
}, CLEANUP_INTERVAL_MS);



app.use(express.json({ limit: '5mb' }));
app.use(express.urlencoded({ extended: true, limit: '5mb' }));
//app.use('/messages', express.json({ limit: '5mb' }));
//app.use('/messages', express.urlencoded({ extended: true, limit: '2mb' }));
//app.use('/allmessages', express.json({ limit: '5mb' }));
//app.use('/allmessages', express.urlencoded({ extended: true, limit: '5mb' }));
//app.use('/getpfp', express.json({ limit: '500kb' }));
//app.use('/getpfp', express.urlencoded({ extended: true, limit: '500kb' }));

const COOLDOWN_HOURS = 24;
const INVITE_LENGTH_BYTES = 4;

//create admin acc
const adminUsername = "admin";
const adminPassword = process.env.ADMIN_PASSWORD;
const hashedPassword = bcrypt.hashSync(adminPassword, 10);

db.get(`SELECT * FROM users WHERE username = ?`, [adminUsername], (err, row) => {
    if (err) return console.error(err.message);
    if (!row) {
        db.run(
            `INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)`,
            [adminUsername, hashedPassword, 'admin'],
            function(err2) {
                if (err2) console.error("Error creating admin user:", err2.message);
                else console.log("Admin user created: username='admin'");
            }
        );
    } else {
        console.log("Admin user already exists");
    }
});

//jwt
function authMiddleware(req, res, next) {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) return res.status(401).json({ error: "No token" });
    try {
        const payload = jwt.verify(token, SECRET_KEY);
        req.userId = payload.id;
        next();
    } catch (e) {
        return res.status(401).json({ error: "Invalid token" });
    }
}


//motd
const motd = "Welcome";
app.get('/motd', (req, res) => {
  res.json({ motd });
});

//version
const ver = "1.5* Please update when the app is released.";
app.get('/version', (req, res) => {
  res.json({ ver });
});

//make invite
function createInvite(userId, res) {
    function tryInsert() {
        const code = crypto.randomBytes(INVITE_LENGTH_BYTES).toString('hex').toUpperCase();
        db.run(
            `INSERT INTO invites (code, created_by) VALUES (?, ?)`,
            [code, userId],
            function(err) {
                if (err && err.message.includes("UNIQUE constraint failed")) return tryInsert();
                if (err) return res.status(500).json({ error: "Internal server error" });
                res.json({ invite_code: code });
            }
        );
    }
    tryInsert();
}

//keycheck
app.get('/conversation/check-key', authMiddleware, (req, res) => {
    const otherId = parseInt(req.query.user_id);
    if (!otherId) return res.status(400).json({ error: "user_id query required" });

    const userPair = [req.userId, otherId].sort((a, b) => a - b);
    const user1 = userPair[0];
    const user2 = userPair[1];

    db.get(
        `SELECT id FROM conversations WHERE user1_id = ? AND user2_id = ?`,
        [user1, user2],
        (err, conversation) => {
            if (err) return res.status(500).json({ error: "Internal server error" });
            if (!conversation) return res.json({ new_key: false });

            const conversationId = conversation.id;

            db.get(
                `SELECT id, aes_key FROM pending_keys WHERE conversation_id = ? AND user_id = ? AND delivered = 0`,
                [conversationId, req.userId],
                (err2, pending) => {
                    if (err2) return res.status(500).json({ error: "Internal server error" });

                    if (pending) {
                        db.run(`DELETE FROM pending_keys WHERE id = ?`, [pending.id], (err3) => {
                            if (err3) console.error("Failed to delete pending key:", err3.message);
                        });
                        return res.json({ new_key: true, aes_key: pending.aes_key });
                    } else {
                        return res.json({ new_key: false });
                    }
                }
            );
        }
    );
});


app.get('/conversation/start', authMiddleware, (req, res) => {
    const otherId = parseInt(req.query.user_id);
    if (!otherId) return res.status(400).json({ error: "user_id query required" });

    const userPair = [req.userId, otherId].sort((a,b) => a-b);
    const user1 = userPair[0];
    const user2 = userPair[1];

    db.get(`SELECT id, aes_key FROM conversations WHERE user1_id = ? AND user2_id = ?`, [user1, user2], (err, convo) => {
        if (err) return res.status(500).json({ error: "Internal server error" });

        if (convo) {
            const conversationId = convo.id;

            db.get(`SELECT id, aes_key FROM pending_keys WHERE user_id = ? AND conversation_id = ? AND delivered = 0`, [req.userId, conversationId], (err2, pending) => {
                if (err2) return res.status(500).json({ error: "Internal server error" });

                if (pending) {
                    db.run(`DELETE FROM pending_keys WHERE id = ?`, [pending.id]);
                    return res.json({ aes_key: pending.aes_key });
                } else {
                    const newKey = crypto.randomBytes(32).toString('base64'); // AES-256

                    db.run(`DELETE FROM messages WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?)`, [user1, user2, user2, user1]);

                    db.run(`UPDATE conversations SET aes_key = ? WHERE id = ?`, [newKey, conversationId], (err3) => {
                        if (err3) return res.status(500).json({ error: "Internal server error" });

                        db.run(`INSERT INTO pending_keys (conversation_id, user_id, aes_key) VALUES (?, ?, ?)`, [conversationId, user1, newKey]);
                        db.run(`INSERT INTO pending_keys (conversation_id, user_id, aes_key) VALUES (?, ?, ?)`, [conversationId, user2, newKey]);

                        db.run(`DELETE FROM pending_keys WHERE conversation_id = ? AND user_id = ?`, [conversationId, req.userId]);

                        res.json({ aes_key: newKey, reset: true });
                    });
                }
            });
        } else {
            const key = crypto.randomBytes(32).toString('base64');

            db.run(`INSERT INTO conversations (user1_id, user2_id, aes_key) VALUES (?, ?, ?)`, [user1, user2, key], function(err4) {
                if (err4) return res.status(500).json({ error: "Internal server error" });
                const conversationId = this.lastID;

                db.run(`INSERT INTO pending_keys (conversation_id, user_id, aes_key) VALUES (?, ?, ?)`, [conversationId, user1, key]);
                db.run(`INSERT INTO pending_keys (conversation_id, user_id, aes_key) VALUES (?, ?, ?)`, [conversationId, user2, key]);

                db.run(`DELETE FROM pending_keys WHERE conversation_id = ? AND user_id = ?`, [conversationId, req.userId]);
                res.json({ aes_key: key, reset: false });
            });
        }
    });
});


const inviteAttemptTimestamps = {};

const BLOCK_TIME_MS = 10 * 60 * 1000; // 10 minutes
const MAX_ATTEMPTS = 20;
const WINDOW_MS = 5000;


//register
app.post('/register', (req, res) => {
    const ip = req.ip;
    const now = Date.now();

    if (!inviteAttemptTimestamps[ip]) {
        inviteAttemptTimestamps[ip] = { timestamps: [], blockedUntil: 0 };
    }

    const data = inviteAttemptTimestamps[ip];

    if (data.blockedUntil > now) {
        const remaining = Math.ceil((data.blockedUntil - now)/1000);
        return res.status(429).json({ error: `Too many requests. Try again in ${remaining} seconds.` });
    }

    data.timestamps = data.timestamps.filter(ts => now - ts < WINDOW_MS);

    data.timestamps.push(now);

    if (data.timestamps.length > MAX_ATTEMPTS) {
        data.blockedUntil = now + BLOCK_TIME_MS;
        data.timestamps = [];
        return res.status(429).json({ error: `Too many requests. You are blocked for 10 minutes.` });
    }

    const { username, password, invite_code } = req.body;
    if (!username || !password || !invite_code) 
        return res.status(400).json({ error: "Missing username, password, or invite code" });

    if (username.length > 20)
        return res.status(400).json({ error: "Username must be at most 20 characters long" });

    if (password.length < 8) 
        return res.status(400).json({ error: "Password must be at least 8 characters long" });

    db.get(`SELECT * FROM invites WHERE code = ? AND used_by IS NULL`, [invite_code], (err, invite) => {
        if (err) return res.status(500).json({ error: "Internal server error" });
        if (!invite) return res.status(400).json({ error: "Invalid invite code" });

        const password_hash = bcrypt.hashSync(password, 10);

        db.run(
            `INSERT INTO users (username, password_hash, invited_by) VALUES (?, ?, ?)`,
            [username, password_hash, invite.created_by],
            function(err) {
                if (err) return res.status(400).json({ error: "Invalid request" });

                const userId = this.lastID;
                db.run(
                    `UPDATE invites SET used_by = ?, used_at = CURRENT_TIMESTAMP WHERE id = ?`,
                    [userId, invite.id],
                    function(err2) {
                        if (err2) console.error("Failed to update invite:", err2.message);
                    }
                );

                res.json({ user_id: userId });
            }
        );
    });
});

//login
const loginAttemptsByIP = {};
const loginAttemptsByUser = {}; 

const LOGIN_MAX_ATTEMPTS = 10;
const LOGIN_WINDOW_MS = 60 * 1000;
const LOGIN_BLOCK_TIME_MS = 15 * 60 * 1000; 

const DUMMY_PASSWORD_HASH = bcrypt.hashSync('DUMMY_PASSWORD_FOR_TIMING', 10);

function cleanupOld(tsArray, windowMs) {
    const now = Date.now();
    while (tsArray.length && now - tsArray[0] > windowMs) {
        tsArray.shift();
    }
}

function isBlocked(storeEntry) {
    if (!storeEntry) return false;
    return storeEntry.blockedUntil && storeEntry.blockedUntil > Date.now();
}

function recordFailedAttempt(store, key) {
    const now = Date.now();
    if (!store[key]) store[key] = { timestamps: [], blockedUntil: 0 };
    const entry = store[key];

    cleanupOld(entry.timestamps, LOGIN_WINDOW_MS);
    entry.timestamps.push(now);

    if (entry.timestamps.length >= LOGIN_MAX_ATTEMPTS) {
        entry.blockedUntil = now + LOGIN_BLOCK_TIME_MS;
        entry.timestamps = []; 
    }
}

function resetAttempts(store, key) {
    if (store[key]) {
        store[key].timestamps = [];
        store[key].blockedUntil = 0;
    }
}

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    const ip = req.ip || req.connection.remoteAddress;

    if (!username || !password) return res.status(400).json({ error: "Missing fields" });

    const ipEntry = loginAttemptsByIP[ip];
    if (isBlocked(ipEntry)) {
        const remaining = Math.ceil((ipEntry.blockedUntil - Date.now()) / 1000);
        return res.status(429).json({ error: `Too many attempts from your IP. Try again in ${remaining} seconds.` });
    }

    const userEntry = loginAttemptsByUser[username];
    if (isBlocked(userEntry)) {
        const remaining = Math.ceil((userEntry.blockedUntil - Date.now()) / 1000);
        return res.status(429).json({ error: `Too many attempts for this account. Try again in ${remaining} seconds.` });
    }

    db.get(`SELECT * FROM users WHERE username = ?`, [username], (err, row) => {
        if (err) return res.status(500).json({ error: "Internal server error" });

        if (!row) {
            bcrypt.compare(password, DUMMY_PASSWORD_HASH, () => {

                recordFailedAttempt(loginAttemptsByIP, ip);
                return res.status(400).json({ error: "Invalid credentials" });
            });
            return;
        }

        bcrypt.compare(password, row.password_hash, (compareErr, same) => {
            if (compareErr) {
                console.error("bcrypt error:", compareErr);
                return res.status(500).json({ error: "Internal error" });
            }

            if (!same) {
                recordFailedAttempt(loginAttemptsByIP, ip);
                recordFailedAttempt(loginAttemptsByUser, username);

                const ipNowEntry = loginAttemptsByIP[ip];
                if (isBlocked(ipNowEntry)) {
                    const remaining = Math.ceil((ipNowEntry.blockedUntil - Date.now()) / 1000);
                    return res.status(429).json({ error: `Too many attempts from your IP. Try again in ${remaining} seconds.` });
                }
                const userNowEntry = loginAttemptsByUser[username];
                if (isBlocked(userNowEntry)) {
                    const remaining = Math.ceil((userNowEntry.blockedUntil - Date.now()) / 1000);
                    return res.status(429).json({ error: `Too many attempts for this account. Try again in ${remaining} seconds.` });
                }

                return res.status(400).json({ error: "Invalid credentials" });
            }

            resetAttempts(loginAttemptsByUser, username);
            resetAttempts(loginAttemptsByIP, ip);

            const token = jwt.sign({ id: row.id }, SECRET_KEY, { expiresIn: '1d' });
            res.json({ token });
        });
    });
});

//username from id
app.get('/username/:id', (req, res) => {
    const userId = parseInt(req.params.id);
    db.get(`SELECT username FROM users WHERE id = ?`, [userId], (err, row) => {
        if (err) return res.status(500).json({ error: "Internal server error" });
        if (!row) return res.status(404).json({ error: "User not found" });
        res.json({ username: row.username });
    });
});

//make the inviteee
app.post('/invites', authMiddleware, (req, res) => {
    db.get(`SELECT role FROM users WHERE id = ?`, [req.userId], (err, user) => {
        if (err) return res.status(500).json({ error: "Internal server error" });
        if (!user) return res.status(404).json({ error: "User not found" });

        const role = user.role || "user";

        //infinite invite creation with roles
        if (role === "admin" || role === "tester") {
            return createInvite(req.userId, res);
        }

        //others
        db.get(
            `SELECT * FROM invites WHERE created_by = ? AND used_by IS NULL LIMIT 1`,
            [req.userId],
            (err2, activeInvite) => {
                if (err2) return res.status(500).json({ error: "Internal server error" });
                if (activeInvite)
                    return res.status(403).json({ error: "You already have an active invite. Wait until it is used." });

                db.get(
                    `SELECT COUNT(*) AS total, MAX(created_at) AS last_created FROM invites WHERE created_by = ?`,
                    [req.userId],
                    (err3, row3) => {
                        if (err3) return res.status(500).json({ error: "Internal server error" });

                        const inviteCount = row3.total || 0;

                        if (row3.last_created) {
                            const lastCreated = new Date(row3.last_created + 'Z'); 
                            const now = new Date();
                            const diffHours = (now - lastCreated) / (1000 * 60 * 60);
                            if (diffHours < COOLDOWN_HOURS) {
                                return res.status(403).json({ error: `You must wait ${Math.ceil(COOLDOWN_HOURS - diffHours)} hours before creating a new invite.` });
                            }
                        }

                        let requiredChats = 0;
                        if (inviteCount === 0) requiredChats = 1;
                        else if (inviteCount === 1) requiredChats = 2;
                        else if (inviteCount === 2) requiredChats = 3;
                        else requiredChats = 5;

                        db.get(
                            `
                            SELECT COUNT(DISTINCT CASE 
                                WHEN sender_id = ? THEN receiver_id
                                WHEN receiver_id = ? THEN sender_id
                            END) AS chatPartners
                            FROM messages
                            WHERE sender_id = ? OR receiver_id = ?;
                            `,
                            [req.userId, req.userId, req.userId, req.userId],
                            (err4, chatRow) => {
                                if (err4) return res.status(500).json({ error: "Internal server error" });
                                const chats = chatRow?.chatPartners || 0;

                                if (chats < requiredChats) {
                                    return res.status(403).json({
                                        error: `You need to have chatted with at least ${requiredChats} unique people before generating this invite. (You have ${chats})`
                                    });
                                }

                                createInvite(req.userId, res);
                            }
                        );
                    }
                );
            }
        );
    });
});

const rateLimitWindowMs = 10 * 1000; // 10 seconds
const maxMessagesPerWindow = 8;

const userMessageTimestamps = {};

// Send message
app.post('/messages', authMiddleware, (req, res) => {
    const { receiver_id, message } = req.body;
    if (!receiver_id || !message) 
        return res.status(400).json({ error: "Missing fields" });
//length
    if (message.length > 700000)
        return res.status(400).json({ error: "Message cannot exceed the length of the universe" });

    const now = Date.now();
    const userId = req.userId;

    if (!userMessageTimestamps[userId]) {
        userMessageTimestamps[userId] = [];
    }

    userMessageTimestamps[userId] = userMessageTimestamps[userId].filter(ts => now - ts < rateLimitWindowMs);

    if (userMessageTimestamps[userId].length >= maxMessagesPerWindow) {
        return res.status(429).json({ error: `Rate limit exceeded. Max ${maxMessagesPerWindow} messages per ${rateLimitWindowMs / 1000} seconds.` });
    }

    userMessageTimestamps[userId].push(now);

    db.run(
        `INSERT INTO messages (sender_id, receiver_id, message) VALUES (?, ?, ?)`,
        [userId, receiver_id, message],
        function(err) {
            if (err) return res.status(500).json({ error: "Internal server error" });
            res.json({ message_id: this.lastID });
        }
    );
});


//get messages
app.get('/messages', authMiddleware, (req, res) => {
    const otherId = req.query.user_id;
    if (!otherId) return res.status(400).json({ error: "user_id query required" });

    const page = parseInt(req.query.page) || 1; // default to page 1
    const limit = 50;
    const offset = (page - 1) * limit;

    db.all(
        `SELECT * FROM (
            SELECT m.id,
            m.sender_id,
            u1.username AS sender_username,
            m.receiver_id,
            u2.username AS receiver_username,
            m.message,
            m.timestamp
            FROM messages m
            JOIN users u1 ON m.sender_id = u1.id
            JOIN users u2 ON m.receiver_id = u2.id
            WHERE (m.sender_id = ? AND m.receiver_id = ?)
            OR (m.sender_id = ? AND m.receiver_id = ?)
            ORDER BY m.timestamp DESC
            LIMIT ? OFFSET ?
        ) sub
        ORDER BY timestamp ASC`,
        [req.userId, otherId, otherId, req.userId, limit, offset],
        (err, rows) => {
            if (err) return res.status(500).json({ error: "Internal server error" });

            const localRows = rows.map(r => {
                const date = new Date(r.timestamp + 'Z');
                r.timestamp = date.toLocaleString();
                return r;
            });

            res.json(localRows);
        }
    );
});

//get ALL messages
app.get('/allmessages', authMiddleware, (req, res) => {
    const otherId = req.query.user_id;
    if (!otherId) return res.status(400).json({ error: "user_id query required" });

    db.all(
        `SELECT * FROM (
            SELECT m.id,
            m.sender_id,
            u1.username AS sender_username,
            m.receiver_id,
            u2.username AS receiver_username,
            m.message,
            m.timestamp
            FROM messages m
            JOIN users u1 ON m.sender_id = u1.id
            JOIN users u2 ON m.receiver_id = u2.id
            WHERE (m.sender_id = ? AND m.receiver_id = ?)
            OR (m.sender_id = ? AND m.receiver_id = ?)
            ORDER BY m.timestamp DESC
        ) sub
        ORDER BY timestamp ASC`,
        [req.userId, otherId, otherId, req.userId],
        (err, rows) => {
            if (err) return res.status(500).json({ error: "Internal server error" });

            const localRows = rows.map(r => {
                const date = new Date(r.timestamp + 'Z');
                r.timestamp = date.toLocaleString();
                return r;
            });

            res.json(localRows);
        }
    );
});

//info
app.get('/me', authMiddleware, (req, res) => {
    db.get(
        `SELECT id, username FROM users WHERE id = ?`,
        [req.userId],
        (err, row) => {
            if (err)
                return res.status(500).json({ error: "Internal server error" });

            if (!row)
                return res.status(404).json({ error: "User not found" });

            res.json(row);
        }
    );
});

app.get('/getpfp', (req, res) => {
    const userId = parseInt(req.query.id);
    if (!userId) return res.status(400).json({ error: "id query parameter required" });

    db.get(
        `SELECT profile_picture FROM users WHERE id = ?`,
        [userId],
        (err, row) => {
            if (err) return res.status(500).json({ error: "Internal server error" });
            if (!row) return res.status(404).json({ error: "User not found" });

            res.json({ profile_picture: row.profile_picture || false });
        }
    );
});


// check for any new messages
app.get('/messages/updates', authMiddleware, (req, res) => {
    const userId = req.userId; 

    db.all(
        `SELECT m.id, m.sender_id, u.username
         FROM messages m
         JOIN users u ON m.sender_id = u.id
         WHERE m.receiver_id = ?
         AND m.id > IFNULL(
             (SELECT last_seen_msg_id FROM users WHERE id = ?),
             0
         )
         ORDER BY m.id DESC`,
        [userId, userId],
        (err, rows) => {
            if (err) {
                console.error('DB error:', err);
                return res.status(500).json({ error: 'Internal server error' });
            }

            if (!rows || rows.length === 0) {
                return res.json({ notification_data: "", all_messages: 0 });
            }

            const latestId = rows[0].id;
            db.run(`UPDATE users SET last_seen_msg_id = ? WHERE id = ?`, [latestId, userId]);

            const senderMap = new Map(); 
            rows.forEach(r => {
                if (!senderMap.has(r.sender_id)) {
                    senderMap.set(r.sender_id, r.username);
                }
            });

            const uniqueNames = Array.from(senderMap.values());

            let notificationStr = "";
            if (uniqueNames.length === 1) {
                notificationStr = `${uniqueNames[0]} sent you a new message`;
            } else if (uniqueNames.length === 2) {
                notificationStr = `${uniqueNames[0]} and ${uniqueNames[1]} sent you a new message`;
            } else if (uniqueNames.length > 2) {
                const allButLast = uniqueNames.slice(0, -1).join(", ");
                const last = uniqueNames[uniqueNames.length - 1];
                notificationStr = `${allButLast}, and ${last} sent you a new message`;
            }

            res.json({ notification_data: notificationStr, all_messages: uniqueNames.length });
        }
    );
});


//message list
app.get('/messages/newmessages', authMiddleware, (req, res) => {
    const userId = req.userId;

    db.all(
        `SELECT m.sender_id, u.username, MAX(m.id) as latest_msg_id
         FROM messages m
         JOIN users u ON m.sender_id = u.id
         WHERE m.receiver_id = ?
         GROUP BY m.sender_id
         ORDER BY latest_msg_id DESC`,
        [userId],
        (err, rows) => {
            if (err) {
                console.error('DB error:', err);
                return res.status(500).json({ error: 'Internal server error' });
            }

            if (!rows || rows.length === 0) {
                return res.json({ updates: [] });
            }

            const updates = rows.map(r => ({
                sender_id: r.sender_id,
                username: r.username
            }));

            res.json({ updates });
        }
    );
});

//upload pfp
app.post('/uploadpfp', authMiddleware, async (req, res) => {
    const { image } = req.body;
    if (!image) return res.status(400).json({ error: "invalid" });

    try {
        const base64Data = image.replace(/^data:image\/\w+;base64,/, "");
        const imgBuffer = Buffer.from(base64Data, 'base64');

        const metadata = await sharp(imgBuffer).metadata();
        if (metadata.width !== 256 || metadata.height !== 256) {
            return res.status(400).json({ error: "invalid" });
        }

        db.run(
            `UPDATE users SET profile_picture = ? WHERE id = ?`,
            [image, req.userId],
            function(err) {
                if (err) return res.status(500).json({ error: "invalid" });
                res.json({ success: true });
            }
        );
    } catch (err) {
        console.error(err);
        return res.status(400).json({ error: "invalid" });
    }
});

const PORT = 8443;
app.listen(PORT, () => {
    console.log(`Node.js server running on http://localhost:${PORT}`);
});
