/*


Summary: The databaseConfig.js is used to create the connection with the server.
*/


var mysql =require('mysql2');
var dbconnect = {

    getConnection: function () {

        var conn = mysql.createConnection({

            host: "localhost",
            user: "root",
            password: "YesNotMaybe_789",
            database: "sp_games"
        })
        return conn;
    }
}

module.exports = dbconnect