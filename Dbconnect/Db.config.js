// db.js
const { Pool } = require('pg');
require('dotenv').config();


// Create a new pool instance with your connection config
const pool = new Pool({
  user: process.env.DB_USER,       // your Postgres username
  host: process.env.DB_HOST,         // database host
  database: process.env.DB_NAME,     // your database name
  password: process.env.DB_PASSWORD, // your user's password
  port: process.env.DB_PORT,                // default Postgres port
});

// Test the connection
pool.connect((err, client, release) => {
  if (err) {
    return console.error('Error acquiring client', err.stack);
  }
  client.query('SELECT NOW()', (err, result) => {
    release();
    if (err) {
      return console.error('Error executing query', err.stack);
    }
    console.log('PostgreSQL connected at:', result.rows[0].now);
  });
});

module.exports = pool;
