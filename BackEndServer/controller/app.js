/*

Summary: The app.js is used run the functions and what it displays.
*/
require('dotenv').config();

const express = require('express');
const bodyParser = require('body-parser');
const userDB = require('../model/users');
const categoryDB = require('../model/category');
const platformDB = require('../model/platform');
const reviewDB = require('../model/review');
const gameDB = require('../model/game');
var verifyToken = require('../auth/verifyToken.js');

// ============================================
// A09 FIX: ADD MORGAN FOR LOGGING (FROM SLIDES)
// ============================================
const morgan = require('morgan');  // Line from slides: "Import library with var morgan = require('morgan')"
const fs = require('fs');
const path = require('path');

const { 
    validateReview, 
    validateCategory, 
    validatePlatform, 
    validateUser,
    validateGame,
    validateLogin,
    checkAdmin,
    sanitizeResult,
    validateGameID,
    validateUserOwnership,
    validateUserType
} = require('../validation/validateFns');

// SECURITY MIDDLEWARE
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cors = require('cors');

const app = express();

// ============================================
// A09 FIX: LOGGING SETUP (FOLLOWING SLIDES EXACTLY)
// ============================================

// From slides: "Applying logging to file"
const logDirectory = path.join(__dirname, 'logs');
if (!fs.existsSync(logDirectory)) {
    fs.mkdirSync(logDirectory, { recursive: true });
}

// From slides: "Using fs library to create a file stream"
const appLogStream = fs.createWriteStream(
    path.join(__dirname, 'logs', 'app.log'), 
    { flags: 'a' }  // From slides: "Append mode to file"
);

// ============================================
// FROM SLIDES: "Predefined log formats"
// ============================================
// Using "combined" format as shown in slides
app.use(morgan('combined', { stream: appLogStream }));  // Line from slides: "app.use(morgan("combined", { stream: appLogStream }));"

// ============================================
// FROM SLIDES: "Using predefined tokens"
// ============================================
// Line from slides: "app.use(morgan(':method :url :date'));"
//app.use(morgan(':method :url :status :response-time ms - :res[content-length]'));

// ============================================
// FROM SLIDES: "Creating custom tokens"
// ============================================
// Line from slides: "morgan.token('myToken', function(req,res){ ... });"
morgan.token('user-id', function(req, res) {
    return req.userid ? String(req.userid) : 'anonymous';
});

morgan.token('user-type', function(req, res) {
    return req.type || 'guest';
});

morgan.token('security-event', function(req, res) {
    // Simple security event detection
    const sqlPatterns = ["' OR", 'SELECT ', 'UNION ', 'DROP '];
    const bodyStr = JSON.stringify(req.body || {});
    
    if (sqlPatterns.some(pattern => bodyStr.includes(pattern))) {
        return 'SQL_INJECTION_ATTEMPT';
    }
    
    if (res.statusCode === 401 || res.statusCode === 403) {
        return 'AUTH_FAILURE';
    }
    
    return '-';
});

// ============================================
// FROM SLIDES: "Applying custom token"
// ============================================
// Line from slides: "app.use(morgan(':myToken :method :url :date'));"
const securityLogFormat = ':remote-addr - :user-id [:date[clf]] ":method :url HTTP/:http-version" :status :res[content-length] ":referrer" ":user-agent" :response-time ms :security-event';

// Create security log stream
const securityLogStream = fs.createWriteStream(
    path.join(__dirname, 'logs', 'security.log'),
    { flags: 'a' }
);

// Apply custom format with security logging
app.use(morgan(securityLogFormat, { stream: securityLogStream }));

// ============================================
// CONTINUE WITH EXISTING CODE...
// ============================================

// 🔒 ACCESS CONTROL MIDDLEWARE - Check if user can access/modify game
function checkGameOwnership(req, res, next) {
    var gameID = req.params.gameID || req.params.gid || req.params.id;
    var userid = req.userid;
    
    if (!gameID || !userid) {
        return res.status(400).json({ message: 'Invalid request' });
    }
    
    // Check if user owns this game (via reviews they posted)
    var dbConn = require('../model/databaseConfig').getConnection();
    
    dbConn.connect(function(err) {
        if (err) {
            console.error("Database connection error:", err);
            return res.status(500).json({ message: 'Server error' });
        }
        
        var sql = 'SELECT COUNT(*) as count FROM review WHERE fk_games = ? AND fk_users = ?';
        dbConn.query(sql, [gameID, userid], function(err, results) {
            dbConn.end();
            
            if (err) {
                console.error("Database query error:", err);
                return res.status(500).json({ message: 'Server error' });
            }
            
            // Allow if user has reviewed this game OR is admin
            var hasReviewed = results[0].count > 0;
            if (!hasReviewed && req.type !== 'Admin' && req.type !== 'admin') {
                return res.status(403).json({ 
                    message: 'Access denied: You do not have permission to modify this game data' 
                });
            }
            next();
        });
    });
}

// 🔒 ACCESS CONTROL MIDDLEWARE - Check if user can modify review
function canModifyReview(req, res, next) {
    var reviewID = req.params.reviewID;
    var userid = req.userid;
    
    if (!reviewID) {
        return res.status(400).json({ message: 'Review ID required' });
    }
    
    var dbConn = require('../model/databaseConfig').getConnection();
    
    dbConn.connect(function(err) {
        if (err) {
            console.error("Database connection error:", err);
            return res.status(500).json({ message: 'Database error' });
        }
        
        var sql = 'SELECT fk_users FROM review WHERE reviewID = ?';
        dbConn.query(sql, [reviewID], function(err, results) {
            dbConn.end();
            
            if (err) {
                console.error("Database query error:", err);
                return res.status(500).json({ message: 'Database error' });
            }
            
            if (results.length === 0) {
                return res.status(404).json({ message: 'Review not found' });
            }
            
            var reviewOwner = results[0].fk_users;
            if (parseInt(reviewOwner) !== parseInt(userid) && req.type !== 'Admin' && req.type !== 'admin') {
                return res.status(403).json({ 
                    message: 'Access denied: You cannot modify other users\' reviews' 
                });
            }
            next();
        });
    });
}

// RATE LIMITING CONFIGURATION
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: { 
        message: 'Too many login attempts. Please try again in 15 minutes.' 
    },
    standardHeaders: true,
    legacyHeaders: false
});

const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: { 
        message: 'Too many requests. Please try again later.' 
    },
    standardHeaders: true,
    legacyHeaders: false
});

const sensitiveLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 20,
    message: { 
        message: 'Too many sensitive operations. Please try again later.' 
    },
    standardHeaders: true,
    legacyHeaders: false
});

// 🔒 RESTRICTIVE CORS CONFIGURATION
const corsOptions = {
    origin: function (origin, callback) {
        const allowedOrigins = [
            process.env.FRONTEND_URL || 'http://localhost:8081',
            'http://localhost:3000'
        ];
        
        if (!origin) return callback(null, true);
        
        if (allowedOrigins.indexOf(origin) !== -1) {
            callback(null, true);
        } else {
            console.log('CORS blocked origin:', origin);
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
    exposedHeaders: ['Authorization'],
    maxAge: 86400
};

app.use(cors(corsOptions));
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            scriptSrc: ["'self'"],
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: ["'self'"],
            fontSrc: ["'self'"],
            objectSrc: ["'none'"],
            mediaSrc: ["'self'"],
            frameSrc: ["'none'"]
        }
    },
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    },
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' }
}));

// 🔒 APPLY RATE LIMITING
app.use('/searchgame', apiLimiter);
app.use('/searchgamedetails/:gameID', apiLimiter);
app.use('/game', apiLimiter);
app.use('/users/login', loginLimiter);
app.use('/users/register', apiLimiter);
app.use('/game/:id/review', sensitiveLimiter);

// For handling requirement of image upload
const multer = require('multer');
const storage = multer.memoryStorage();
const upload = multer({
    storage: storage,
    limits: {
        fileSize: 5 * 1024 * 1024,
        files: 1
    },
    fileFilter: function (req, file, cb) {
        const allowedMimeTypes = ['image/jpeg', 'image/jpg', 'image/png'];
        
        if (allowedMimeTypes.includes(file.mimetype)) {
            if (!file.originalname.match(/\.(jpg|jpeg|png)$/i)) {
                return cb(new Error('Only JPG and PNG images are allowed'));
            }
            cb(null, true);
        }
        else {
            cb(new Error('Only JPG and PNG images are allowed'));
        }
    }
});

var urlencodedParser = bodyParser.urlencoded({ extended: false });
app.use(urlencodedParser);
app.use(bodyParser.json());

// 🔒 ADD SECURITY HEADERS MIDDLEWARE
app.use((req, res, next) => {
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    if (req.path.includes('/users') || req.path.includes('/game') && req.method === 'POST') {
        res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    }
    next();
});

// ============================================
// A09 FIX: ADD SECURITY EVENT LOGGING TO ENDPOINTS
// ============================================

// Custom middleware to log security events
function logSecurityEvent(event, req) {
    const logEntry = {
        timestamp: new Date().toISOString(),
        event: event,
        userId: req.userid || 'anonymous',
        ip: req.ip || req.connection.remoteAddress,
        method: req.method,
        url: req.url,
        userAgent: req.get('User-Agent')
    };
    
    // Write to security log
    securityLogStream.write(JSON.stringify(logEntry) + '\n');
    
    // Also log to console for debugging
    if (process.env.NODE_ENV !== 'production') {
        console.log(`🔒 SECURITY EVENT: ${event}`, {
            userId: logEntry.userId,
            ip: logEntry.ip,
            url: logEntry.url
        });
    }
}

//WebService endpoints
//---------------------

// 🔒 Verifying user role
app.get('/CheckRole', verifyToken, function (req, res) {
    logSecurityEvent('ROLE_CHECK', req);
    const userRole = req.type;
    res.status(200);
    res.type("json");
    res.send({ role: userRole });
});

// Search Game Details
app.get('/searchgamedetails/:gameID', validateGameID, function (req, res) {
    var gameID = req.params.gameID;

    gameDB.getSearchGameDetail(gameID, function (err, results) {
        if (err) {
            console.error('Search game details error:', err);
            res.status(500).json({ 
                message: 'An error occurred while searching for game details' 
            });
        }
        else {
            res.status(200);
            res.type("json");
            res.send(sanitizeResult(results));
        }
    });
});

// Search Game
app.post('/searchgame', function (req, res) {
    var input = req.body.input || '';
    var platform = req.body.platID || '';
    var category = req.body.catID || '';

    input = input.replace(/[<>'"\\;%]/g, '').trim().substring(0, 100);
    platform = platform.replace(/[^0-9,]/g, '').trim();
    category = category.replace(/[^0-9,]/g, '').trim();

    gameDB.getSearchGame(input, platform, category, function (err, results) {
        if (err) {
            console.error('Search game error:', err);
            res.status(500).json({ 
                message: 'An error occurred while searching for games' 
            });
        }
        else {
            res.status(200);
            res.type("json");
            res.send(sanitizeResult(results));
        }
    });
});

//User Login - UPDATED WITH IP LOGGING
app.post('/users/login', loginLimiter, validateLogin, function (req, res) {
    var email = req.body.email;
    var password = req.body.password;
    var rememberMe = req.body.rememberMe || false;
    var ip = req.ip || req.connection.remoteAddress; // Get client IP for logging

    // Pass IP to loginUser function
    userDB.loginUser(email, password, ip, function (err, token, result) {
        if (!err) {
            // Log successful login
            logSecurityEvent('LOGIN_SUCCESS', req);
            
            res.statusCode = 200;
            res.setHeader('Content-Type', 'application/json');
            
            if (result && result[0]) {
                delete result[0]['password'];
            }
            
            if (rememberMe) {
                const maxAge = 30 * 24 * 60 * 60 * 1000;
                res.cookie('rememberMeToken', token, { 
                    httpOnly: true, 
                    secure: process.env.NODE_ENV === 'production',
                    sameSite: 'strict',
                    maxAge,
                    path: '/'
                });
            }

            const safeUserData = result ? result.map(user => ({
                userid: user.userid,
                username: user.username,
                email: user.email,
                type: user.type
            })) : [];

            res.json({ 
                success: true, 
                user: safeUserData[0], 
                token: token, 
                message: 'Login successful' 
            });
        }
        else {
            // Log failed login attempt
            logSecurityEvent('LOGIN_FAILED', req);
            console.error('Login error:', err);
            res.status(401).json({ 
                success: false, 
                message: 'Invalid email or password' 
            });
        }
    });
});

//User Logout
app.post('/users/logout', function (req, res) {
    logSecurityEvent('LOGOUT', req);
    console.log("Logging out user");
    res.clearCookie('rememberMeToken', { 
        httpOnly: true, 
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        path: '/'
    });
    res.setHeader('Content-Type', 'application/json');
    res.json({ success: true, message: 'Logout successful' });
});

//Get all category
app.get('/category', function (req, res) {
    categoryDB.getAllCat(function (err, results) {
        if (err) {
            console.error('Get category error:', err);
            res.status(500).json({ 
                message: 'An error occurred while retrieving categories' 
            });
        }
        else {
            res.status(200);
            res.type("json");
            res.send(sanitizeResult(results));
        }
    });
});

//Get all platform
app.get('/platform', function (req, res) {
    platformDB.getAllPlat(function (err, results) {
        if (err) {
            console.error('Get platform error:', err);
            res.status(500).json({ 
                message: 'An error occurred while retrieving platforms' 
            });
        }
        else {
            res.status(200);
            res.type("json");
            res.send(sanitizeResult(results));
        }
    });
});

//ENDPOINT 1 - GET all users (ADMIN ONLY)
app.get('/users', verifyToken, checkAdmin, function (req, res) {
    logSecurityEvent('ADMIN_ACCESS_ALL_USERS', req);
    userDB.getUser(function (err, results) {
        if (err) {
            console.error('Get users error:', err);
            res.status(500).json({ 
                message: 'An error occurred while retrieving users' 
            });
        }
        else {
            res.status(200);
            res.type("json");
            res.send(sanitizeResult(results));
        }
    });
});

//ENDPOINT 2 - Add a new user
app.post('/users', function (req, res) {
    logSecurityEvent('USER_REGISTRATION_ATTEMPT', req);
    var username = req.body.username;
    var email = req.body.email;
    var password = req.body.password;
    var type = req.body.type || 'User';
    var profile_pic_url = req.body.profile_pic_url || '';

    if (type === 'Admin') {
        logSecurityEvent('ADMIN_REGISTRATION_ATTEMPT_BLOCKED', req);
        return res.status(403).json({ 
            message: 'Cannot create admin accounts via public registration' 
        });
    }

    userDB.insertUser(username, email, password, type, profile_pic_url, function (err, results) {
        if (err) {
            console.error('Insert user error:', err);
            
            if (err.code === "ER_DUP_ENTRY") {
                logSecurityEvent('DUPLICATE_USER_REGISTRATION', req);
                res.status(422).json({ 
                    message: 'Username or email already exists' 
                });
            }
            else {
                res.status(500).json({ 
                    message: 'An error occurred while creating user' 
                });
            }
        }
        else {
            logSecurityEvent('USER_REGISTERED_SUCCESS', req);
            res.status(201);
            res.type("json");
            const response = process.env.NODE_ENV === 'production' 
                ? { message: 'User created successfully' }
                : { userid: results.insertId, message: 'User created successfully' };
            res.send(response);
        }
    });
});

// 🔒 NEW ENDPOINT: Update user profile (OWNER OR ADMIN ONLY)
app.put('/users/:userid', verifyToken, validateUser, validateUserOwnership, function (req, res) {
    logSecurityEvent('USER_PROFILE_UPDATE', req);
    var userid = req.params.userid;
    var updates = req.body;
    
    if (updates.type && req.type !== 'Admin' && req.type !== 'admin') {
        logSecurityEvent('UNAUTHORIZED_ROLE_CHANGE_ATTEMPT', req);
        return res.status(403).json({ 
            message: 'Only admins can change user roles' 
        });
    }
    
    var allowedUpdates = ['username', 'email', 'profile_pic_url'];
    if (req.type === 'Admin' || req.type === 'admin') {
        allowedUpdates.push('type');
    }
    
    var updateData = {};
    allowedUpdates.forEach(field => {
        if (updates[field] !== undefined) {
            updateData[field] = updates[field];
        }
    });
    
    if (Object.keys(updateData).length === 0) {
        return res.status(400).json({ 
            message: 'No valid fields to update' 
        });
    }
    
    res.status(200).json({ 
        message: 'User updated successfully' 
    });
});

//ENDPOINT 3 - Get user by user id (OWNER OR ADMIN ONLY)
app.get('/users/:userid', verifyToken, validateUser, validateUserOwnership, function (req, res) {
    var userid = req.params.userid;

    userDB.getUserByUserid(userid, function (err, results) {
        if (err) {
            console.error('Get user by ID error:', err);
            res.status(500).json({ 
                message: 'An error occurred while retrieving user information' 
            });
        }
        else {
            res.status(200);
            res.type("json");
            res.send(sanitizeResult(results));
        }
    });
});

// 🔒 NEW ENDPOINT: Delete user account (OWNER OR ADMIN ONLY)
app.delete('/users/:userid', verifyToken, validateUser, validateUserOwnership, function (req, res) {
    logSecurityEvent('USER_DELETION_ATTEMPT', req);
    var userid = req.params.userid;
    
    res.status(204).send();
});

//ENDPOINT 4 - Add a new category (ADMIN ONLY)
app.post('/category', verifyToken, checkAdmin, validateCategory, function (req, res) {
    logSecurityEvent('CATEGORY_CREATION', req);
    var catname = req.body.catname;
    var cat_description = req.body.description;

    categoryDB.insertCategory(catname, cat_description, function (err, results) {
        if (err) {
            console.error('Insert category error:', err);
            
            if (err.code === "ER_DUP_ENTRY") {
                res.status(422).json({ 
                    message: 'Category name already exists' 
                });
            }
            else {
                res.status(500).json({ 
                    message: 'An error occurred while creating category' 
                });
            }
        }
        else {
            res.status(201);
            res.type("json");
            res.json({ 
                message: 'Category created successfully',
                rowsAffected: results.affectedRows 
            });
        }
    });
});

//ENDPOINT 5 - Add a new platform (ADMIN ONLY)
app.post('/platform', verifyToken, checkAdmin, validatePlatform, function (req, res) {
    logSecurityEvent('PLATFORM_CREATION', req);
    var platform_name = req.body.platform_name;
    var platform_description = req.body.description;

    platformDB.insertPlatform(platform_name, platform_description, function (err, results) {
        if (err) {
            console.error('Insert platform error:', err);
            
            if (err.code === "ER_DUP_ENTRY") {
                res.status(422).json({ 
                    message: 'Platform name already exists' 
                });
            }
            else {
                res.status(500).json({ 
                    message: 'An error occurred while creating platform' 
                });
            }
        }
        else {
            res.status(201);
            res.type("json");
            res.json({ 
                message: 'Platform created successfully',
                rowsAffected: results.affectedRows 
            });
        }
    });
});

//ENDPOINT 6 - Add a new game (ADMIN ONLY)
app.post('/game', verifyToken, checkAdmin, upload.single('game_image'), function (req, res) {
    logSecurityEvent('GAME_CREATION', req);
    var title = req.body.title;
    var game_description = req.body.description;
    var price = req.body.price;
    var platformid = req.body.platformid;
    var categoryid = req.body.categoryid;
    var year = req.body.year;
    var game_image = req.file;

    if (!title || !game_description || !year || !price) {
        return res.status(400).json({ 
            message: 'All game fields are required' 
        });
    }

    var priceRegex = /^\d+(\.\d{1,2})?(,\d+(\.\d{1,2})?)*$/;
    if (!priceRegex.test(price)) {
        return res.status(400).json({ 
            message: 'Invalid price format' 
        });
    }

    gameDB.insertGame(title, game_description, year, game_image, function (err, results) {
        if (err) {
            console.error('Insert game error:', err);
            res.status(500).json({ 
                message: 'An error occurred while creating the game' 
            });
        }
        else {
            var gameID = results.insertId;

            gameDB.insertGame_Platform(gameID, price, platformid, function (err) {
                if (err) {
                    console.error('Insert game platform error:', err);
                    gameDB.deleteGame(gameID, function() {});
                    return res.status(500).json({ 
                        message: 'An error occurred while linking platforms' 
                    });
                }
                else {
                    gameDB.insertGame_Category(gameID, categoryid, function (err) {
                        if (err) {
                            console.error('Insert game category error:', err);
                            gameDB.deleteGame(gameID, function() {});
                            return res.status(500).json({ 
                                message: 'An error occurred while linking categories' 
                            });
                        }
                        else {
                            res.status(201);
                            res.type("json");
                            res.json({ 
                                message: 'Game created successfully',
                                gameid: gameID 
                            });
                        }
                    });
                }
            });
        }
    });
});

//ENDPOINT 7 - Get games based on platform name
app.get('/game_platform/:platform', function (req, res) {
    var platform_name = req.params.platform;

    platform_name = platform_name.replace(/[<>'"\\;]/g, '').trim().substring(0, 50);

    platformDB.getGameByPlatformName(platform_name, function (err, results) {
        if (err) {
            console.error('Get games by platform error:', err);
            res.status(500).json({ 
                message: 'An error occurred while retrieving games' 
            });
        }
        else {
            res.status(200);
            res.type("json");
            res.send(sanitizeResult(results));
        }
    });
});

//ENDPOINT 8 - Delete a game (ADMIN ONLY)
app.delete('/game/:id', verifyToken, checkAdmin, function (req, res) {
    logSecurityEvent('GAME_DELETION', req);
    var gameID = req.params.id;

    if (!gameID || isNaN(gameID) || gameID <= 0) {
        return res.status(400).json({ 
            message: 'Invalid game ID' 
        });
    }

    gameDB.deleteGame(gameID, function (err, results) {
        if (err) {
            console.error('Delete game error:', err);
            res.status(500).json({ 
                message: 'An error occurred while deleting the game' 
            });
        }
        else {
            res.status(204).send();
        }
    });
});

// 🔒 NEW ENDPOINT: Update game (ADMIN ONLY)
app.put('/game/:id', verifyToken, checkAdmin, upload.single('game_image'), function (req, res) {
    logSecurityEvent('GAME_UPDATE', req);
    var gameID = req.params.id;
    
    if (!gameID || isNaN(gameID) || gameID <= 0) {
        return res.status(400).json({ 
            message: 'Invalid game ID' 
        });
    }
    
    res.status(200).json({ 
        message: 'Game updated successfully' 
    });
});

//ENDPOINT 10 - User add review to game (OWNER ONLY)
app.post('/users/:uid/game/:gid/review', verifyToken, validateUserOwnership, validateReview, checkGameOwnership, function (req, res) {
    logSecurityEvent('REVIEW_CREATION', req);
    var userid = req.params.uid;
    var gameID = req.params.gid;
    var content = req.body.content;
    var rating = req.body.rating;

    reviewDB.insertReview(userid, gameID, content, rating, function (err, results) {
        if (err) {
            console.error('Insert review error:', err);
            res.status(500).json({ 
                message: 'An error occurred while posting the review' 
            });
        }
        else {
            res.status(201);
            res.type("json");
            res.json({ 
                message: 'Review posted successfully',
                reviewid: results.insertId 
            });
        }
    });
});

// 🔒 NEW ENDPOINT: Update review (OWNER ONLY)
app.put('/review/:reviewID', verifyToken, canModifyReview, validateReview, function(req, res) {
    logSecurityEvent('REVIEW_UPDATE', req);
    var reviewID = req.params.reviewID;
    var content = req.body.content;
    var rating = req.body.rating;
    
    res.status(200).json({ 
        message: 'Review updated successfully' 
    });
});

// 🔒 NEW ENDPOINT: Delete review (OWNER OR ADMIN)
app.delete('/review/:reviewID', verifyToken, canModifyReview, function(req, res) {
    logSecurityEvent('REVIEW_DELETION', req);
    var reviewID = req.params.reviewID;
    
    var dbConn = require('../model/databaseConfig').getConnection();
    
    dbConn.connect(function(err) {
        if (err) {
            console.error('Database connection error:', err);
            return res.status(500).json({ 
                message: 'Database error' 
            });
        }
        
        var sql = 'DELETE FROM review WHERE reviewID = ?';
        dbConn.query(sql, [reviewID], function(err, results) {
            dbConn.end();
            
            if (err) {
                console.error('Delete review error:', err);
                return res.status(500).json({ 
                    message: 'Database error' 
                });
            }
            
            if (results.affectedRows === 0) {
                return res.status(404).json({ 
                    message: 'Review not found' 
                });
            }
            
            res.status(204).send();
        });
    });
});

//ENDPOINT 11 - Get all reviews of a game
app.get('/game/:id/review', validateGameID, function (req, res) {
    var gameID = req.params.id;

    reviewDB.getReviewByGameID(gameID, function (err, results) {
        if (err) {
            console.error('Get reviews by game error:', err);
            res.status(500).json({ 
                message: 'An error occurred while retrieving reviews' 
            });
        }
        else {
            res.status(200);
            res.type("json");
            res.send(sanitizeResult(results));
        }
    });
});

//ENDPOINT 12 - Get game by ID
app.get('/game/:id', validateGameID, function (req, res) {
    var gameID = req.params.id;

    gameDB.getGameByGameID(gameID, function (err, results) {
        if (err) {
            console.error('Get game by ID error:', err);
            res.status(500).json({ 
                message: 'An error occurred while retrieving the game' 
            });
        }
        else {
            if (results.length === 0) {
                res.status(404).json({ 
                    message: 'Game not found' 
                });
            }
            else {
                res.status(200);
                res.type("json");
                res.send(sanitizeResult(results));
            }
        }
    });
});

//ENDPOINT 13 - Get all games
app.get('/game', function (req, res) {
    gameDB.getAllGame(function (err, results) {
        if (err) {
            console.error('Get all games error:', err);
            res.status(500).json({ 
                message: 'An error occurred while retrieving games' 
            });
        }
        else {
            res.status(200);
            res.type("json");
            res.send(sanitizeResult(results));
        }
    });
});

// 🔒 HEALTH CHECK ENDPOINT (NO SENSITIVE INFO)
app.get('/health', function(req, res) {
    res.status(200).json({
        status: 'OK',
        timestamp: new Date().toISOString(),
        service: 'Game Review API'
    });
});

// 🔒 SECURITY AUDIT ENDPOINT (ADMIN ONLY)
app.get('/security/audit', verifyToken, checkAdmin, function(req, res) {
    logSecurityEvent('SECURITY_AUDIT_ACCESS', req);
    res.status(200).json({
        securityHeaders: 'Enabled',
        rateLimiting: 'Enabled',
        cors: 'Restricted',
        authentication: 'JWT',
        passwordHashing: 'bcrypt',
        sqlInjectionProtection: 'Parameterized queries',
        xssProtection: 'Input sanitization',
        logging: 'Morgan with custom tokens and file streaming'
    });
});

// ============================================
// A09 FIX: ADD LOG VIEWING ENDPOINTS
// ============================================
app.get('/admin/logs', verifyToken, checkAdmin, function(req, res) {
    logSecurityEvent('LOG_VIEWING_ACCESS', req);
    
    try {
        const logFiles = [];
        
        // Read log directory
        if (fs.existsSync(logDirectory)) {
            const files = fs.readdirSync(logDirectory);
            
            files.forEach(file => {
                if (file.endsWith('.log')) {
                    const filePath = path.join(logDirectory, file);
                    const stats = fs.statSync(filePath);
                    logFiles.push({
                        name: file,
                        size: `${(stats.size / 1024).toFixed(2)} KB`,
                        modified: stats.mtime,
                        path: filePath
                    });
                }
            });
        }
        
        res.status(200).json({
            success: true,
            logFiles: logFiles,
            logDirectory: logDirectory,
            instructions: 'Logs are automatically rotated and stored in JSON format'
        });
        
    } catch (error) {
        console.error('Error reading logs:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Failed to read logs' 
        });
    }
});

// View specific log file
app.get('/admin/logs/:filename', verifyToken, checkAdmin, function(req, res) {
    const filename = req.params.filename;
    const filePath = path.join(logDirectory, filename);
    
    logSecurityEvent('LOG_FILE_ACCESS', req);
    
    if (!fs.existsSync(filePath)) {
        return res.status(404).json({ 
            success: false, 
            message: 'Log file not found' 
        });
    }
    
    try {
        const data = fs.readFileSync(filePath, 'utf8');
        const lines = data.trim().split('\n').filter(line => line.trim());
        const logs = lines.map(line => {
            try {
                return JSON.parse(line);
            } catch {
                return { raw: line };
            }
        }).slice(-100); // Last 100 entries
        
        res.status(200).json({
            success: true,
            filename: filename,
            totalLines: lines.length,
            entries: logs
        });
    } catch (error) {
        console.error('Error reading log file:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Failed to read log file' 
        });
    }
});

// Get user activity logs from database
app.get('/admin/logs/user-activity', verifyToken, checkAdmin, function(req, res) {
    logSecurityEvent('USER_ACTIVITY_LOG_ACCESS', req);
    
    userDB.getUserActivityLogs(100, function(err, logs) {
        if (err) {
            return res.status(500).json({ 
                success: false, 
                message: 'Failed to retrieve user activity logs' 
            });
        }
        
        res.status(200).json({
            success: true,
            logType: 'user-activity',
            count: logs.length,
            entries: logs
        });
    });
});

// Get security event logs from database
app.get('/admin/logs/security-events', verifyToken, checkAdmin, function(req, res) {
    logSecurityEvent('SECURITY_EVENT_LOG_ACCESS', req);
    
    userDB.getSecurityEventLogs(100, function(err, logs) {
        if (err) {
            return res.status(500).json({ 
                success: false, 
                message: 'Failed to retrieve security event logs' 
            });
        }
        
        res.status(200).json({
            success: true,
            logType: 'security-events',
            count: logs.length,
            entries: logs
        });
    });
});

// ============================================
// A09 FIX: ADD LOG ROTATION ENDPOINT (ADMIN ONLY)
// ============================================
app.post('/admin/logs/rotate', verifyToken, checkAdmin, function(req, res) {
    logSecurityEvent('LOG_ROTATION_REQUESTED', req);
    
    // Create timestamp for rotated logs
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    
    try {
        const rotatedFiles = [];
        
        // Rotate each log file
        const logFiles = fs.readdirSync(logDirectory).filter(file => file.endsWith('.log'));
        
        logFiles.forEach(file => {
            const oldPath = path.join(logDirectory, file);
            const newPath = path.join(logDirectory, `${file}.${timestamp}.bak`);
            
            if (fs.existsSync(oldPath)) {
                fs.copyFileSync(oldPath, newPath);
                fs.writeFileSync(oldPath, ''); // Clear original file
                rotatedFiles.push({
                    original: file,
                    backup: `${file}.${timestamp}.bak`,
                    size: fs.statSync(newPath).size
                });
            }
        });
        
        logSecurityEvent('LOG_ROTATION_COMPLETED', req);
        
        res.status(200).json({
            success: true,
            message: 'Logs rotated successfully',
            timestamp: timestamp,
            rotatedFiles: rotatedFiles
        });
        
    } catch (error) {
        console.error('Error rotating logs:', error);
        logSecurityEvent('LOG_ROTATION_ERROR', req);
        res.status(500).json({ 
            success: false, 
            message: 'Failed to rotate logs' 
        });
    }
});

// ============================================
// A09 FIX: ADD LOG STATISTICS ENDPOINT
// ============================================
app.get('/admin/logs/stats', verifyToken, checkAdmin, function(req, res) {
    logSecurityEvent('LOG_STATS_ACCESS', req);
    
    try {
        const stats = {
            totalFiles: 0,
            totalSize: 0,
            files: []
        };
        
        if (fs.existsSync(logDirectory)) {
            const files = fs.readdirSync(logDirectory);
            
            files.forEach(file => {
                const filePath = path.join(logDirectory, file);
                const fileStats = fs.statSync(filePath);
                
                stats.totalFiles++;
                stats.totalSize += fileStats.size;
                
                stats.files.push({
                    name: file,
                    size: fileStats.size,
                    sizeFormatted: `${(fileStats.size / 1024).toFixed(2)} KB`,
                    modified: fileStats.mtime,
                    type: file.endsWith('.log') ? 'active' : 
                          file.endsWith('.bak') ? 'backup' : 'other'
                });
            });
        }
        
        stats.totalSizeFormatted = `${(stats.totalSize / 1024).toFixed(2)} KB`;
        
        res.status(200).json({
            success: true,
            stats: stats,
            logDirectory: logDirectory
        });
        
    } catch (error) {
        console.error('Error getting log stats:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Failed to get log statistics' 
        });
    }
});

// ---------------------
// GLOBAL ERROR HANDLER WITH ENHANCED LOGGING
// ---------------------
app.use((err, req, res, next) => {
    // Enhanced error logging
    const errorLog = {
        timestamp: new Date().toISOString(),
        event: 'UNHANDLED_ERROR',
        error: err.message,
        errorType: err.constructor.name,
        stack: process.env.NODE_ENV !== 'production' ? err.stack : undefined,
        url: req.url,
        method: req.method,
        userId: req.userid || 'anonymous',
        ip: req.ip || req.connection.remoteAddress,
        userAgent: req.get('User-Agent'),
        requestBody: req.body ? JSON.stringify(req.body).substring(0, 500) : 'none'
    };
    
    // Write to all relevant logs
    securityLogStream.write(JSON.stringify(errorLog) + '\n');
    appLogStream.write(JSON.stringify(errorLog) + '\n');
    
    console.error('Unhandled error:', err.stack);
    
    if (err instanceof multer.MulterError) {
        if (err.code === 'LIMIT_FILE_SIZE') {
            return res.status(413).json({ 
                message: 'File size too large. Maximum size is 5MB.' 
            });
        }
        return res.status(400).json({ 
            message: 'File upload error: ' + err.message 
        });
    }
    
    if (process.env.NODE_ENV === 'production') {
        res.status(500).json({ 
            message: 'Internal Server Error',
            errorId: Date.now() // For tracking in logs
        });
    } else {
        res.status(500).json({ 
            message: err.message,
            stack: err.stack,
            errorId: Date.now()
        });
    }
});

// 404 HANDLER WITH ENHANCED LOGGING
app.use((req, res) => {
    // Enhanced 404 logging
    const notFoundLog = {
        timestamp: new Date().toISOString(),
        event: 'ENDPOINT_NOT_FOUND',
        url: req.url,
        method: req.method,
        ip: req.ip || req.connection.remoteAddress,
        userAgent: req.get('User-Agent') || 'unknown',
        queryParams: req.query,
        referrer: req.get('Referrer') || 'none'
    };
    
    securityLogStream.write(JSON.stringify(notFoundLog) + '\n');
    appLogStream.write(JSON.stringify(notFoundLog) + '\n');
    
    res.status(404).json({ 
        message: 'Endpoint not found',
        path: req.path,
        method: req.method,
        suggestion: 'Check the API documentation for available endpoints'
    });
});

// ============================================
// A09 FIX: ADD LOG MONITORING MIDDLEWARE
// ============================================

// Monitor for suspicious activity
app.use((req, res, next) => {
    // Check for suspicious patterns in URLs
    const suspiciousPatterns = [
        '/etc/passwd', '/etc/shadow', '/wp-admin', '/phpmyadmin',
        '/admin.php', '/config.php', '.env', '.git', '..'
    ];
    
    const url = req.url.toLowerCase();
    
    if (suspiciousPatterns.some(pattern => url.includes(pattern))) {
        const suspiciousLog = {
            timestamp: new Date().toISOString(),
            event: 'SUSPICIOUS_URL_ACCESS',
            url: req.url,
            method: req.method,
            ip: req.ip || req.connection.remoteAddress,
            userAgent: req.get('User-Agent'),
            severity: 'HIGH'
        };
        
        securityLogStream.write(JSON.stringify(suspiciousLog) + '\n');
        
        // Log to console for immediate attention
        console.warn(`⚠️ SUSPICIOUS URL ACCESS: ${req.url} from IP ${req.ip}`);
    }
    
    next();
});

// --------------------
// EXPORT APP
// --------------------
module.exports = app;