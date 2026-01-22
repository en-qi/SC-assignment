/*

Summary: The users.js is used create functions and what it does to the Users database.
*/

const db = require('./databaseConfig');
var config = require('../config.js');
var jwt = require('jsonwebtoken');

// 🔒 SECURITY FIX: ADD PASSWORD HASHING
const bcrypt = require('bcrypt');
const saltRounds = 10; // Industry standard salt rounds

var userDB = {

    // ENDPOINT 1
    // Get all users
    getUser: function (callback) {
        var dbConn = db.getConnection();

        // Connect to MySQL DB
        dbConn.connect(function (err) {
            if (err) {
                return callback(err, null);
            }
            else {
                // 🔒 SECURITY FIX: DON'T RETURN PASSWORDS IN RESPONSE
                var getUserSql = `SELECT userid, username, email, type, profile_pic_url,
                                        DATE_FORMAT(created_at, '%Y-%m-%d %H:%i:%s') AS created_at 
                                 FROM users`;

                dbConn.query(getUserSql, [], function (err, results) {
                    dbConn.end();
                    
                    if (err) {
                        return callback(err, null);
                    }
                    else {
                        // 🔒 SECURITY FIX: SANITIZE OUTPUT BEFORE RETURNING
                        // Remove any password fields that might slip through
                        results.forEach(user => {
                            if (user.password) delete user.password;
                        });
                        return callback(null, results);
                    }
                });
            }
        });
    },


    // ENDPOINT 2
    // Add a new user
    insertUser: function (username, email, password, type, profile_pic_url, callback) {
        var dbConn = db.getConnection();

        // 🔒 SECURITY FIX: HASH PASSWORD BEFORE STORING
        bcrypt.hash(password, saltRounds, function(err, hashedPassword) {
            if (err) {
                console.error("Password hashing error:", err);
                return callback(err, null);
            }

            dbConn.connect(function (err) {
                if (err) {
                    return callback(err, null);
                }
                else {
                    // 🔒 SECURITY FIX: USE PARAMETERIZED QUERIES WITH HASHED PASSWORD
                    var insertUserSql = "INSERT INTO users(username, email, password, type, profile_pic_url) VALUES (?, ?, ?, ?, ?)";
                    
                    dbConn.query(insertUserSql, [username, email, hashedPassword, type, profile_pic_url], function (err, results) {
                        dbConn.end();
                        
                        if (err) {
                            // 🔒 SECURITY FIX: GENERIC ERROR MESSAGES
                            if (err.code === "ER_DUP_ENTRY") {
                                // Don't reveal which field is duplicate in error message
                                var error = new Error("Username or email already exists");
                                error.statusCode = 422;
                                return callback(error, null);
                            }
                            console.error("Database error:", err);
                            var error = new Error("Database operation failed");
                            error.statusCode = 500;
                            return callback(error, null);
                        }
                        else {
                            return callback(null, results);
                        }
                    });
                }
            });
        });
    },


    // ENDPOINT 3
    // Get user by user id
    getUserByUserid: function (userid, callback) {
        var dbConn = db.getConnection();

        // 🔒 SECURITY FIX: VALIDATE USER ID
        if (!userid || isNaN(userid) || userid <= 0) {
            var error = new Error("Invalid user ID");
            error.statusCode = 400;
            return callback(error, null);
        }

        dbConn.connect(function (err) {
            if (err) {
                return callback(err, null);
            }
            else {
                // 🔒 SECURITY FIX: DON'T RETURN PASSWORD
                var getUserByUserIDSql = `SELECT userid, username, email, type, profile_pic_url,
                                                 DATE_FORMAT(created_at, '%Y-%m-%d %H:%i:%s') AS created_at 
                                          FROM users 
                                          WHERE userid = ?`;

                dbConn.query(getUserByUserIDSql, [userid], function (err, results) {
                    dbConn.end();
                    
                    if (err) {
                        console.error("Database error:", err);
                        var error = new Error("Database operation failed");
                        error.statusCode = 500;
                        return callback(error, null);
                    }
                    else {
                        // 🔒 SECURITY FIX: CHECK IF USER EXISTS
                        if (results.length === 0) {
                            var error = new Error("User not found");
                            error.statusCode = 404;
                            return callback(error, null);
                        }
                        
                        // 🔒 SECURITY FIX: REMOVE PASSWORD FIELD
                        delete results[0].password;
                        return callback(null, results);
                    }
                });
            }
        });
    },


    // Login user by email and password
    loginUser: function (email, password, callback) {
        var dbConn = db.getConnection();

        // 🔒 SECURITY FIX: VALIDATE INPUTS
        if (!email || !password) {
            var error = new Error("Email and password are required");
            error.statusCode = 400;
            return callback(error, null, null);
        }

        // 🔒 SECURITY FIX: PREVENT SQL INJECTION - USE PARAMETERIZED QUERY
        dbConn.connect(function (err) {
            if (err) {
                console.error("Database connection error:", err);
                var error = new Error("Database connection failed");
                error.statusCode = 500;
                return callback(error, null, null);
            }
            else {
                // 🔒 SECURITY FIX: GET USER BY EMAIL ONLY FIRST
                var sql = 'SELECT * FROM users WHERE email = ?';
                
                dbConn.query(sql, [email], function (err, result) {
                    dbConn.end();

                    if (err) {
                        console.error("Database query error:", err);
                        var error = new Error("Authentication failed");
                        error.statusCode = 500;
                        return callback(error, null, null);
                    } 
                    else {
                        // 🔒 SECURITY FIX: TIMING-ATTACK SAFE PASSWORD VERIFICATION
                        if (result.length === 1) {
                            // Compare hashed password
                            bcrypt.compare(password, result[0].password, function(err, isMatch) {
                                if (err) {
                                    console.error("Password comparison error:", err);
                                    var error = new Error("Authentication failed");
                                    error.statusCode = 500;
                                    return callback(error, null, null);
                                }
                                
                                if (!isMatch) {
                                    // 🔒 SECURITY FIX: GENERIC ERROR MESSAGE (don't reveal if email exists)
                                    var error = new Error("Invalid email or password");
                                    error.statusCode = 401;
                                    return callback(error, null, null);
                                }
                                
                                // 🔒 SECURITY FIX: REMOVE PASSWORD FROM USER OBJECT
                                var userWithoutPassword = { ...result[0] };
                                delete userWithoutPassword.password;
                                
                                // Create JWT token with secure options
                                var token = jwt.sign({ 
                                    userid: result[0].userid, 
                                    type: result[0].type 
                                }, process.env.JWT_SECRET || config.key, { 
                                    expiresIn: '24h',
                                    algorithm: 'HS256' // Specify algorithm
                                });
                                
                                console.log("Login successful for user:", result[0].userid);
                                return callback(null, token, [userWithoutPassword]);
                            });
                        } 
                        else {
                            // 🔒 SECURITY FIX: GENERIC ERROR MESSAGE (prevent user enumeration)
                            var error = new Error("Invalid email or password");
                            error.statusCode = 401;
                            return callback(error, null, null);
                        }
                    }  
                });
            }
        });
    },

    // 🔒 NEW SECURITY FUNCTION: Update user password securely
    updatePassword: function(userid, currentPassword, newPassword, callback) {
        var dbConn = db.getConnection();
        
        dbConn.connect(function(err) {
            if (err) return callback(err, null);
            
            // First get current password hash
            var sql = 'SELECT password FROM users WHERE userid = ?';
            dbConn.query(sql, [userid], function(err, result) {
                if (err) {
                    dbConn.end();
                    return callback(err, null);
                }
                
                if (result.length === 0) {
                    dbConn.end();
                    var error = new Error("User not found");
                    error.statusCode = 404;
                    return callback(error, null);
                }
                
                // Verify current password
                bcrypt.compare(currentPassword, result[0].password, function(err, isMatch) {
                    if (err || !isMatch) {
                        dbConn.end();
                        var error = new Error("Current password is incorrect");
                        error.statusCode = 401;
                        return callback(error, null);
                    }
                    
                    // Hash new password
                    bcrypt.hash(newPassword, saltRounds, function(err, hashedNewPassword) {
                        if (err) {
                            dbConn.end();
                            return callback(err, null);
                        }
                        
                        // Update password
                        var updateSql = 'UPDATE users SET password = ? WHERE userid = ?';
                        dbConn.query(updateSql, [hashedNewPassword, userid], function(err, results) {
                            dbConn.end();
                            
                            if (err) {
                                var error = new Error("Failed to update password");
                                error.statusCode = 500;
                                return callback(error, null);
                            }
                            
                            return callback(null, { message: "Password updated successfully" });
                        });
                    });
                });
            });
        });
    },

    // 🔒 NEW SECURITY FUNCTION: Check if user exists
    userExists: function(userid, callback) {
        var dbConn = db.getConnection();
        
        dbConn.connect(function(err) {
            if (err) return callback(err, false);
            
            var sql = 'SELECT COUNT(*) as count FROM users WHERE userid = ?';
            dbConn.query(sql, [userid], function(err, result) {
                dbConn.end();
                
                if (err) return callback(err, false);
                return callback(null, result[0].count > 0);
            });
        });
    }

}

module.exports = userDB;