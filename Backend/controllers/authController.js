const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const db = require('../config/db');

const register = (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ message: 'Email and password are required' });
    }

    bcrypt.hash(password, 10, (err, hashedPassword) => {
        if (err) {
            return res.status(500).json({ message: 'Error hashing password' });
        }

        const query = 'INSERT INTO users (email, password) VALUES (?, ?)';
        db.query(query, [email, hashedPassword], (err, results) => {
            if (err) {
                return res.status(500).json({ message: 'Error registering user' });
            }

            res.status(201).json({ message: 'User registered successfully' });
        });
    });
};

const login = (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ message: 'Email and password are required' });
    }

    const query = 'SELECT * FROM users WHERE email = ?';
    db.query(query, [email], (err, results) => {
        if (err) {
            return res.status(500).json({ message: 'Error fetching user' });
        }

        if (results.length === 0) {
            return res.status(401).json({ message: 'Invalid email or password' });
        }

        const user = results[0];

        bcrypt.compare(password, user.password, (err, isMatch) => {
            if (err) {
                return res.status(500).json({ message: 'Error comparing passwords' });
            }

            if (!isMatch) {
                return res.status(401).json({ message: 'Invalid email or password' });
            }

            const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });

            res.status(200).json({ token });
        });
    });
};

const logout = (req, res) => {
    res.status(200).json({ message: 'Successfully logged out' });
};

module.exports = { register, login, logout };
