// backend/config/db.js
const mysql = require('mysql2');
require('dotenv').config();

const connection = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD || '', // Default to empty string if not set
    database: process.env.DB_NAME,
});

connection.connect((err) => {
    if (err) {
        console.error('Database connection failed:', err);
        return;
    }
    console.log('Connected to database.');
});

module.exports = connection;
