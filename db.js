const mysql = require('mysql2');
const conn = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'project2' 
})
conn.connect((err) => {
    if (err){
        console.error ('Error connecting to the database:', err.stack);
        return;
    }
    console.log('Connected to the database as ID', conn.threadId);
});
module.exports = conn;