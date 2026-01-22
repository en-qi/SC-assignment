/*


Summary: The databaseConfig.js is used to create the connection with the server.
*/
require('dotenv').config();

var mysql = require('mysql2');
var dbconnect = {
    getConnection: function () {
        var conn = mysql.createConnection({
            host: process.env.DB_HOST || "localhost",
            user: process.env.DB_USER || "root",
            password: process.env.DB_PASSWORD || "root1",
            database: process.env.DB_NAME || "sp_games",
            multipleStatements: false,
            connectTimeout: 10000
        })
        return conn;
    }
}
module.exports = dbconnect