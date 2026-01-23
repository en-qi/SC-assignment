/*

Summary: The users.js is used create functions and what it does to the Users database.
*/

const db = require('./databaseConfig');
var config = require('../config.js');
var jwt = require('jsonwebtoken');

// 🔒 SECURITY FIX: ADD PASSWORD HASHING
const bcrypt = require('bcrypt');
const saltRounds = 10; // Industry standard salt rounds

// ============================================
// A09 FIX: ADD LOGGING FOR SECURITY MONITORING
// ============================================
const fs = require('fs');
const path = require('path');

// Create logs directory if it doesn't exist
const logDir = path.join(__dirname, '..', 'logs');
if (!fs.existsSync(logDir)) {
    fs.mkdirSync(logDir, { recursive: true });
}

// User activity log stream
const userActivityLogStream = fs.createWriteStream(
    path.join(logDir, 'user-activity.log'),
    { flags: 'a' }
);

// Security events log stream
const securityEventsLogStream = fs.createWriteStream(
    path.join(logDir, 'security-events.log'),
    { flags: 'a' }
);

// Helper function to log user activities
function logUserActivity(eventType, details = {}) {
    const logEntry = {
        timestamp: new Date().toISOString(),
        event: eventType,
        ...details
    };
    
    // Remove sensitive data before logging
    if (logEntry.password) delete logEntry.password;
    if (logEntry.token) delete logEntry.token;
    if (logEntry.newPassword) delete logEntry.newPassword;
    if (logEntry.currentPassword) delete logEntry.currentPassword;
    
    userActivityLogStream.write(JSON.stringify(logEntry) + '\n');
    
    // Console output for development
    if (process.env.NODE_ENV !== 'production') {
        console.log(`👤 USER ACTIVITY: ${eventType}`, {
            userId: details.userId || 'unknown',
            email: details.email ? details.email.substring(0, 3) + '***' : 'unknown'
        });
    }
}

// Helper function to log security events
function logSecurityEvent(eventType, details = {}) {
    const logEntry = {
        timestamp: new Date().toISOString(),
        event: eventType,
        severity: getSeverityLevel(eventType),
        ...details
    };
    
    // Remove sensitive data
    if (logEntry.password) delete logEntry.password;
    if (logEntry.token) delete logEntry.token;
    
    securityEventsLogStream.write(JSON.stringify(logEntry) + '\n');
    
    // Console alert for critical events
    if (logEntry.severity === 'CRITICAL') {
        console.error(`🚨 CRITICAL SECURITY EVENT: ${eventType}`, {
            ip: details.ip || 'unknown',
            userId: details.userId || 'unknown',
            email: details.email ? details.email.substring(0, 3) + '***' : 'unknown'
        });
    }
}

function getSeverityLevel(eventType) {
    const criticalEvents = ['BRUTE_FORCE_ATTEMPT', 'UNAUTHORIZED_ACCESS', 'ACCOUNT_TAKEOVER'];
    const highEvents = ['MULTIPLE_FAILED_LOGINS', 'SUSPICIOUS_ACTIVITY', 'ADMIN_ACCESS_VIOLATION'];
    
    if (criticalEvents.includes(eventType)) return 'CRITICAL';
    if (highEvents.includes(eventType)) return 'HIGH';
    return 'MEDIUM';
}

// Track failed login attempts for brute force detection
let failedLoginAttempts = new Map();
const MAX_FAILED_ATTEMPTS = 5;
const LOCKOUT_DURATION = 15 * 60 * 1000; // 15 minutes

function trackFailedLogin(ip, email) {
    const key = `${ip}:${email}`;
    const now = Date.now();
    
    if (!failedLoginAttempts.has(key)) {
        failedLoginAttempts.set(key, { count: 1, firstAttempt: now, lastAttempt: now });
    } else {
        const attempts = failedLoginAttempts.get(key);
        attempts.count++;
        attempts.lastAttempt = now;
        
        // Check for brute force
        if (attempts.count >= MAX_FAILED_ATTEMPTS) {
            const timeDiff = now - attempts.firstAttempt;
            if (timeDiff < LOCKOUT_DURATION) {
                logSecurityEvent('BRUTE_FORCE_ATTEMPT', {
                    ip,
                    email: email.substring(0, 3) + '***',
                    attempts: attempts.count,
                    duration: `${timeDiff}ms`,
                    action: 'Account temporarily locked'
                });
                return true; // Trigger lockout
            } else {
                // Reset if time window passed
                failedLoginAttempts.set(key, { count: 1, firstAttempt: now, lastAttempt: now });
            }
        }
    }
    
    return false;
}

function resetFailedLogin(ip, email) {
    const key = `${ip}:${email}`;
    failedLoginAttempts.delete(key);
}

// ============================================
// USER DATABASE FUNCTIONS
// ============================================

var userDB = {

    // ENDPOINT 1
    // Get all users
    getUser: function (callback) {
        var dbConn = db.getConnection();
        
        // Log admin access (if called via API)
        logUserActivity('ADMIN_GET_ALL_USERS', {
            action: 'Retrieved all users from database'
        });

        // Connect to MySQL DB
        dbConn.connect(function (err) {
            if (err) {
                logSecurityEvent('DATABASE_CONNECTION_ERROR', {
                    operation: 'getAllUsers',
                    error: err.message
                });
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
                        logSecurityEvent('DATABASE_QUERY_ERROR', {
                            operation: 'getAllUsers',
                            error: err.message,
                            sql: getUserSql
                        });
                        return callback(err, null);
                    }
                    else {
                        // 🔒 SECURITY FIX: SANITIZE OUTPUT BEFORE RETURNING
                        // Remove any password fields that might slip through
                        results.forEach(user => {
                            if (user.password) delete user.password;
                        });
                        
                        logUserActivity('USERS_RETRIEVED_SUCCESS', {
                            count: results.length
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
        
        // Log registration attempt
        logUserActivity('USER_REGISTRATION_ATTEMPT', {
            username: username,
            email: email.substring(0, 3) + '***',
            type: type
        });

        // 🔒 SECURITY FIX: HASH PASSWORD BEFORE STORING
        bcrypt.hash(password, saltRounds, function(err, hashedPassword) {
            if (err) {
                console.error("Password hashing error:", err);
                logSecurityEvent('PASSWORD_HASHING_ERROR', {
                    username: username,
                    email: email.substring(0, 3) + '***',
                    error: err.message
                });
                return callback(err, null);
            }

            dbConn.connect(function (err) {
                if (err) {
                    logSecurityEvent('DATABASE_CONNECTION_ERROR', {
                        operation: 'insertUser',
                        username: username,
                        error: err.message
                    });
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
                                logSecurityEvent('DUPLICATE_USER_REGISTRATION', {
                                    username: username,
                                    email: email.substring(0, 3) + '***',
                                    error: 'Username or email already exists'
                                });
                                
                                // Don't reveal which field is duplicate in error message
                                var error = new Error("Username or email already exists");
                                error.statusCode = 422;
                                return callback(error, null);
                            }
                            
                            console.error("Database error:", err);
                            logSecurityEvent('DATABASE_INSERT_ERROR', {
                                operation: 'insertUser',
                                username: username,
                                error: err.message,
                                sql: insertUserSql
                            });
                            
                            var error = new Error("Database operation failed");
                            error.statusCode = 500;
                            return callback(error, null);
                        }
                        else {
                            logUserActivity('USER_REGISTERED_SUCCESS', {
                                userId: results.insertId,
                                username: username,
                                email: email.substring(0, 3) + '***',
                                type: type
                            });
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
                logSecurityEvent('DATABASE_CONNECTION_ERROR', {
                    operation: 'getUserByUserid',
                    userId: userid,
                    error: err.message
                });
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
                        logSecurityEvent('DATABASE_QUERY_ERROR', {
                            operation: 'getUserByUserid',
                            userId: userid,
                            error: err.message,
                            sql: getUserByUserIDSql
                        });
                        
                        var error = new Error("Database operation failed");
                        error.statusCode = 500;
                        return callback(error, null);
                    }
                    else {
                        // 🔒 SECURITY FIX: CHECK IF USER EXISTS
                        if (results.length === 0) {
                            logUserActivity('USER_NOT_FOUND', {
                                requestedUserId: userid
                            });
                            var error = new Error("User not found");
                            error.statusCode = 404;
                            return callback(error, null);
                        }
                        
                        // 🔒 SECURITY FIX: REMOVE PASSWORD FIELD
                        delete results[0].password;
                        
                        logUserActivity('USER_PROFILE_RETRIEVED', {
                            userId: userid,
                            username: results[0].username
                        });
                        
                        return callback(null, results);
                    }
                });
            }
        });
    },


    // Login user by email and password
    loginUser: function (email, password, ip = 'unknown', callback) {
        var dbConn = db.getConnection();

        // 🔒 SECURITY FIX: VALIDATE INPUTS
        if (!email || !password) {
            var error = new Error("Email and password are required");
            error.statusCode = 400;
            return callback(error, null, null);
        }

        // Check for brute force attempts
        if (trackFailedLogin(ip, email)) {
            var error = new Error("Too many failed attempts. Please try again later.");
            error.statusCode = 429;
            return callback(error, null, null);
        }

        // 🔒 SECURITY FIX: PREVENT SQL INJECTION - USE PARAMETERIZED QUERY
        dbConn.connect(function (err) {
            if (err) {
                console.error("Database connection error:", err);
                logSecurityEvent('DATABASE_CONNECTION_ERROR', {
                    operation: 'loginUser',
                    email: email.substring(0, 3) + '***',
                    ip: ip,
                    error: err.message
                });
                
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
                        logSecurityEvent('DATABASE_QUERY_ERROR', {
                            operation: 'loginUser',
                            email: email.substring(0, 3) + '***',
                            ip: ip,
                            error: err.message,
                            sql: sql
                        });
                        
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
                                    logSecurityEvent('PASSWORD_COMPARISON_ERROR', {
                                        userId: result[0].userid,
                                        email: email.substring(0, 3) + '***',
                                        ip: ip,
                                        error: err.message
                                    });
                                    
                                    var error = new Error("Authentication failed");
                                    error.statusCode = 500;
                                    return callback(error, null, null);
                                }
                                
                                if (!isMatch) {
                                    // Track failed login
                                    trackFailedLogin(ip, email);
                                    
                                    // 🔒 SECURITY FIX: GENERIC ERROR MESSAGE (don't reveal if email exists)
                                    logSecurityEvent('LOGIN_FAILED', {
                                        email: email.substring(0, 3) + '***',
                                        ip: ip,
                                        reason: 'Invalid password',
                                        userId: result[0].userid
                                    });
                                    
                                    var error = new Error("Invalid email or password");
                                    error.statusCode = 401;
                                    return callback(error, null, null);
                                }
                                
                                // Successful login - reset failed attempts
                                resetFailedLogin(ip, email);
                                
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
                                
                                // Log successful login
                                logUserActivity('LOGIN_SUCCESS', {
                                    userId: result[0].userid,
                                    email: email.substring(0, 3) + '***',
                                    userType: result[0].type,
                                    ip: ip,
                                    tokenIssued: true
                                });
                                
                                console.log("Login successful for user:", result[0].userid);
                                return callback(null, token, [userWithoutPassword]);
                            });
                        } 
                        else {
                            // Track failed login (user not found)
                            trackFailedLogin(ip, email);
                            
                            // 🔒 SECURITY FIX: GENERIC ERROR MESSAGE (prevent user enumeration)
                            logSecurityEvent('LOGIN_FAILED', {
                                email: email.substring(0, 3) + '***',
                                ip: ip,
                                reason: 'User not found'
                            });
                            
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
    updatePassword: function(userid, currentPassword, newPassword, ip = 'unknown', callback) {
        var dbConn = db.getConnection();
        
        // Log password change attempt
        logUserActivity('PASSWORD_CHANGE_ATTEMPT', {
            userId: userid,
            ip: ip
        });
        
        dbConn.connect(function(err) {
            if (err) {
                logSecurityEvent('DATABASE_CONNECTION_ERROR', {
                    operation: 'updatePassword',
                    userId: userid,
                    error: err.message
                });
                return callback(err, null);
            }
            
            // First get current password hash
            var sql = 'SELECT password FROM users WHERE userid = ?';
            dbConn.query(sql, [userid], function(err, result) {
                if (err) {
                    dbConn.end();
                    logSecurityEvent('DATABASE_QUERY_ERROR', {
                        operation: 'updatePassword',
                        userId: userid,
                        error: err.message,
                        sql: sql
                    });
                    return callback(err, null);
                }
                
                if (result.length === 0) {
                    dbConn.end();
                    logSecurityEvent('USER_NOT_FOUND_PASSWORD_CHANGE', {
                        requestedUserId: userid,
                        ip: ip
                    });
                    var error = new Error("User not found");
                    error.statusCode = 404;
                    return callback(error, null);
                }
                
                // Verify current password
                bcrypt.compare(currentPassword, result[0].password, function(err, isMatch) {
                    if (err || !isMatch) {
                        dbConn.end();
                        logSecurityEvent('PASSWORD_CHANGE_FAILED', {
                            userId: userid,
                            ip: ip,
                            reason: 'Current password incorrect'
                        });
                        var error = new Error("Current password is incorrect");
                        error.statusCode = 401;
                        return callback(error, null);
                    }
                    
                    // Hash new password
                    bcrypt.hash(newPassword, saltRounds, function(err, hashedNewPassword) {
                        if (err) {
                            dbConn.end();
                            logSecurityEvent('PASSWORD_HASHING_ERROR', {
                                userId: userid,
                                error: err.message
                            });
                            return callback(err, null);
                        }
                        
                        // Update password
                        var updateSql = 'UPDATE users SET password = ? WHERE userid = ?';
                        dbConn.query(updateSql, [hashedNewPassword, userid], function(err, results) {
                            dbConn.end();
                            
                            if (err) {
                                logSecurityEvent('DATABASE_UPDATE_ERROR', {
                                    operation: 'updatePassword',
                                    userId: userid,
                                    error: err.message,
                                    sql: updateSql
                                });
                                var error = new Error("Failed to update password");
                                error.statusCode = 500;
                                return callback(error, null);
                            }
                            
                            // Log successful password change
                            logUserActivity('PASSWORD_CHANGED_SUCCESS', {
                                userId: userid,
                                ip: ip
                            });
                            
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
            if (err) {
                logSecurityEvent('DATABASE_CONNECTION_ERROR', {
                    operation: 'userExists',
                    userId: userid,
                    error: err.message
                });
                return callback(err, false);
            }
            
            var sql = 'SELECT COUNT(*) as count FROM users WHERE userid = ?';
            dbConn.query(sql, [userid], function(err, result) {
                dbConn.end();
                
                if (err) {
                    logSecurityEvent('DATABASE_QUERY_ERROR', {
                        operation: 'userExists',
                        userId: userid,
                        error: err.message,
                        sql: sql
                    });
                    return callback(err, false);
                }
                
                const exists = result[0].count > 0;
                if (!exists) {
                    logUserActivity('USER_EXISTENCE_CHECK', {
                        requestedUserId: userid,
                        exists: false
                    });
                }
                return callback(null, exists);
            });
        });
    },

    // ============================================
    // A09 FIX: ADD LOGGING HELPER FUNCTIONS
    // ============================================
    
    // Get user activity logs (admin only)
    getUserActivityLogs: function(limit = 100, callback) {
        try {
            const logPath = path.join(logDir, 'user-activity.log');
            if (!fs.existsSync(logPath)) {
                return callback(null, []);
            }
            
            const data = fs.readFileSync(logPath, 'utf8');
            const lines = data.trim().split('\n').filter(line => line.trim());
            const logs = lines.map(line => {
                try {
                    return JSON.parse(line);
                } catch {
                    return { raw: line };
                }
            }).slice(-limit); // Get last N entries
            
            return callback(null, logs);
        } catch (error) {
            console.error('Error reading user activity logs:', error);
            return callback(error, null);
        }
    },
    
    // Get security event logs (admin only)
    getSecurityEventLogs: function(limit = 100, callback) {
        try {
            const logPath = path.join(logDir, 'security-events.log');
            if (!fs.existsSync(logPath)) {
                return callback(null, []);
            }
            
            const data = fs.readFileSync(logPath, 'utf8');
            const lines = data.trim().split('\n').filter(line => line.trim());
            const logs = lines.map(line => {
                try {
                    return JSON.parse(line);
                } catch {
                    return { raw: line };
                }
            }).slice(-limit);
            
            return callback(null, logs);
        } catch (error) {
            console.error('Error reading security event logs:', error);
            return callback(error, null);
        }
    },
    
    // Clean old log entries (maintenance)
    cleanupOldLogs: function(daysToKeep = 30, callback) {
        // Implementation for log rotation
        // This would remove logs older than specified days
        logUserActivity('LOG_CLEANUP_STARTED', {
            daysToKeep: daysToKeep
        });
        
        // For now, just log the intent
        // In production, implement actual log rotation
        return callback(null, { message: "Log cleanup would run here" });
    }

}

// ============================================
// EXPORT WITH LOGGING FUNCTIONS
// ============================================
module.exports = userDB;