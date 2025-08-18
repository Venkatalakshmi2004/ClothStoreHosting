const fs = require('fs');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();

const dataDirectoryPath = path.join(__dirname, '..', 'data');
const databaseFilePath = path.join(dataDirectoryPath, 'app.db');

if (!fs.existsSync(dataDirectoryPath)) {
    fs.mkdirSync(dataDirectoryPath, { recursive: true });
}

const database = new sqlite3.Database(databaseFilePath);

// Initialize schema
database.serialize(() => {
    database.run(
        `CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT DEFAULT (datetime('now'))
        )`
    );
});

function runQuery(sql, params = []) {
    return new Promise((resolve, reject) => {
        database.run(sql, params, function runCallback(error) {
            if (error) return reject(error);
            resolve(this);
        });
    });
}

function getQuery(sql, params = []) {
    return new Promise((resolve, reject) => {
        database.get(sql, params, function getCallback(error, row) {
            if (error) return reject(error);
            resolve(row);
        });
    });
}

async function createUser(email, passwordHash) {
    await runQuery(
        `INSERT INTO users (email, password_hash) VALUES (?, ?)`,
        [email, passwordHash]
    );
}

async function findUserByEmail(email) {
    return await getQuery(`SELECT * FROM users WHERE email = ?`, [email]);
}

async function getUserById(userId) {
    return await getQuery(`SELECT * FROM users WHERE id = ?`, [userId]);
}

module.exports = {
    createUser,
    findUserByEmail,
    getUserById,
};

