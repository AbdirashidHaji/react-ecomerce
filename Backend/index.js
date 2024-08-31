const express = require('express');
const app = express();
const cors = require('cors');
const authRoutes = require('./routes/authRoutes');

require('dotenv').config();

app.use(cors());
app.use(express.json());
app.use('/api', authRoutes);

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
