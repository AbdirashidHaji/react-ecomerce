// backend/models/User.js
const db = require('../config/db');
const bcrypt = require('bcryptjs');

const User = {};

User.create = (newUser, result) => {
    const query = 'INSERT INTO users SET ?';
    bcrypt.hash(newUser.password, 10, (err, hash) => {
        if (err) throw err;
        newUser.password = hash;
        db.query(query, newUser, (err, res) => {
            if (err) {
                result(err, null);
                return;
            }
            result(null, { id: res.insertId, ...newUser });
        });
    });
};

User.findByEmail = (email, result) => {
    const query = 'SELECT * FROM users WHERE email = ?';
    db.query(query, [email], (err, res) => {
        if (err) {
            result(err, null);
            return;
        }
        if (res.length) {
            result(null, res[0]);
            return;
        }
        result({ kind: 'not_found' }, null);
    });
};

module.exports = User;
