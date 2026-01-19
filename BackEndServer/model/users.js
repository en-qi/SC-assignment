/*


Summary: The users.js is used create functions and what it does to the Users database.
*/

const db = require('./databaseConfig');
var config = require('../config.js');
var jwt = require('jsonwebtoken');


var userDB = {

    //ENDPOINT 1
    //Get all users
    getUser: function (callback) {
        var dbConn = db.getConnection();

        // Connect to MySQL DB
        dbConn.connect(function (err) {
            if (err) {

                return callback(err, null);
            }

            else {

                var getUserSql = `select userid, username, email, password, type, profile_pic_url,
                                    DATE_FORMAT(created_at, '%Y-%m-%d %H:%i:%s') AS created_at FROM users`;

                dbConn.query(getUserSql, [], function (err, results) {

                    if (err) {

                        dbConn.end();
                        return callback(err, null);
                    }

                    else {

                        dbConn.end();
                        return callback(null, results);
                    }
                });
            }
        });
    },


    //ENDPOINT 2
    //Add a new user
    insertUser: function (username, email, password, type, profile_pic_url, callback) {

        var dbConn = db.getConnection();

        dbConn.connect(function (err) {

            if (err) {

                return callback(err, null);
            }

            else {

                var insertUserSql = "insert into users(username,email,password,type,profile_pic_url) values(?,?,?,?,?)";
                dbConn.query(insertUserSql, [username, email, password, type, profile_pic_url], function (err, results) {

                    if (err) {

                        dbConn.end();
                        return callback(err, null);
                    }

                    else {

                        dbConn.end();
                        return callback(err, results);
                    }
                })
            }
        });
    },


    //ENDPOINT 3
    //Get user by user id
    getUserByUserid: function (userid, callback) {

        var dbConn = db.getConnection();

        dbConn.connect(function (err) {

            if (err) {

                return callback(err, null);
            }

            else {

                var getUserByUserIDSql = `select userid, username, email, password, type, profile_pic_url,
                                            DATE_FORMAT(created_at, '%Y-%m-%d %H:%i:%s') AS created_at FROM users where userid = ${userid};`;

                dbConn.query(getUserByUserIDSql, [], function (err, results) {

                    if (err) {

                        dbConn.end();
                        return callback(err, null);
                    }

                    else {

                        dbConn.end();
                        return callback(err, results);
                    }
                })
            }
        });
    },


    //Login user by email and password
    loginUser: function (email, password, callback) {

		var dbConn = db.getConnection();

		dbConn.connect(function (err) {

			if (err) {

				console.log(err);
				return callback(err, null);
			}

			else {
				var sql = 'select * from users where email=? and password=?';

				dbConn.query(sql, [email, password], function (err, result) {
					dbConn.end();

					if (err) {

						console.log("Err: " + err);
						return callback(err, null, null);
					} 
                    
                    else {
						var token = "";
						var i;

						if (result.length == 1) {

							token = jwt.sign({ userid: result[0].userid, type: result[0].type }, config.key, {expiresIn: 86400}); //expires in 24 hrs
							console.log("@@token " + token);
							return callback(null, token, result);
						} 
                        
                        else {

							var err2 = new Error("UserID/Password does not match.");
							err2.statusCode = 500;
							return callback(err2, null, null);
						}
					}  
				});
			}
		});
	},

}
module.exports = userDB;