const { Pool } = require('pg');

const pool = new Pool({
    host: process.env.DB_HOST || 'db',
    port: process.env.DB_PORT || 5432,
    database: process.env.DB_NAME || 'dlp_demo',
    user: process.env.DB_USER || 'dlp_admin',
    password: process.env.DB_PASS || 'dlpsecurate'
});

pool.on('error', (err) => {
    console.error('Error en pool de PostgreSQL:', err);
});

module.exports = pool;
