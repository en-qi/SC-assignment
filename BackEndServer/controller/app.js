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

const { 
    validateReview, 
    validateCategory, 
    validatePlatform, 
    validateUser,
    validateGame,
    validateLogin,
    checkAdmin,
    sanitizeResult,
    validateGameID  // ← ADD THIS LINE
} = require('../validation/validateFns');

// SECURITY MIDDLEWARE
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cors = require('cors');

const app = express();

// RATE LIMITING CONFIGURATION
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: 'Too many login attempts, please try again later'
});

const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100
});

// RESTRICTIVE CORS CONFIGURATION
const corsOptions = {
    origin: process.env.FRONTEND_URL || 'http://localhost:3000',
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
};

app.use(cors(corsOptions));
app.use(helmet());

// Apply rate limiting to public endpoints
app.use('/searchgame', apiLimiter);
app.use('/searchgamedetails/:gameID', apiLimiter);
app.use('/game', apiLimiter);

// For handling requirement of image upload
const multer = require('multer');
const storage = multer.memoryStorage();     // Store uploaded image file in memory
const upload = multer({
    storage: storage,
    limits: {                           // ← ADD THIS SECTION
        fileSize: 5 * 1024 * 1024,     // 5MB limit
        files: 1                       // Only 1 file
    },
    fileFilter: function (req, file, cb) {
        // Accept only JPG image with proper extension
        if (file.mimetype === 'image/jpeg' || file.mimetype === 'image/jpg') {
            // Also check filename extension
            if (!file.originalname.match(/\.(jpg|jpeg)$/i)) {
                return cb(new Error('Only JPEG images are allowed'));
            }
            cb(null, true);
        }
        // Reject other file type
        else {
            cb(new Error('Only JPEG images are allowed'));
        }
    }
});



var urlencodedParser = bodyParser.urlencoded({ extended: false });
app.use(urlencodedParser);  //attach body-parser middleware
app.use(bodyParser.json()); //parse json data


//WebService endpoints
//---------------------


// Verifying user role
app.get('/CheckRole',verifyToken, function (req, res) {

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

            console.log(err);

            res.status(500);
            res.type("json");
            res.send(`{"Message":"some error encounted!"}`);
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

    var input = req.body.input;
    var platform = req.body.platID;
    var category = req.body.catID;

    // Basic input sanitization
    input = input ? input.replace(/[<>'"\\;]/g, '').trim() : '';
    platform = platform ? platform.replace(/[<>'"\\;]/g, '').trim() : '';
    category = category ? category.replace(/[<>'"\\;]/g, '').trim() : '';

    gameDB.getSearchGame(input, platform, category, function (err, results) {

        if (err) {

            console.log(err);

            res.status(500);
            res.type("json");
            res.send(`{"Message":"some error encounted!"}`);
        }

        else {

            res.status(200);
            res.type("json");
            res.send(sanitizeResult(results));
        }
    });
});


//User Login
app.post('/users/login', loginLimiter, validateLogin, function (req, res) {
    var email = req.body.email;
    var password = req.body.password;
    var rememberMe = req.body.rememberMe || false;

    userDB.loginUser(email, password, function (err, token, result) {

        if (!err) {

            res.statusCode = 200;
            res.setHeader('Content-Type', 'application/json');
            delete result[0]['password'];//clear the password in json data, do not send back to client
            console.log(result);

            // If rememberMe is true, set a cookie with the token for persistent login
            if (rememberMe) {
                const maxAge = 30 * 24 * 60 * 60 * 1000; // 30 days in milliseconds
                res.cookie('rememberMeToken', token, { httpOnly: true, maxAge });
            }

            res.json({ success: true, UserData: JSON.stringify(result), token: token, status: 'You are successfully logged in!' });
            res.send();
        }

        else {
    console.log('Login error:', err);
    res.status(500).json({ 
        success: false, 
        message: 'Login failed. Please check your credentials.' 
    });
}
    });
});


//User Logout
app.post('/users/logout', function (req, res) {
    console.log("..logging out.");
    res.clearCookie('rememberMeToken'); //clears the cookie in the response
    res.setHeader('Content-Type', 'application/json');
    res.json({ success: true, status: 'Log out successful!' });
});


//Get all category
app.get('/category', function (req, res) {


    categoryDB.getAllCat(function (err, results) {

        // If Any error occur
        if (err) {

            console.log(err);

            res.status(500);
            res.type("json");
            res.send(`{"Message":"Internal Server Error"}`);
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

        // If Any error occur
        if (err) {

            console.log(err);

            res.status(500);
            res.type("json");
            res.send(`{"Message":"Internal Server Error"}`);
        }

        else {

            res.status(200);
            res.type("json");
            res.send(sanitizeResult(results));
        }
    });
});

//ENDPOINT 1
//GET /user/
//Get all users
app.get('/users', verifyToken, checkAdmin, function (req, res) {


    userDB.getUser(function (err, results) {

        // If Any error occur
        if (err) {

            console.log(err);

            res.status(500);
            res.type("json");
            res.send(`{"Message":"Internal Server Error"}`);
        }

        else {

            res.status(200);
            res.type("json");
            res.send(sanitizeResult(results));
        }
    });
});


//ENDPOINT 2
//POST /user
//Add a new user
app.post('/users', function (req, res) {

    //retrieve user input
    var username = req.body.username;
    var email = req.body.email;
    var password = req.body.password;
    var type = req.body.type;
    var profile_pic_url = req.body.profile_pic_url;


    userDB.insertUser(username, email, password, type, profile_pic_url, function (err, results) {

        if (err) {

            // Check for Duplication Entry
            if (err.code === "ER_DUP_ENTRY") {

                // Duplicate entry error for the username
                if (err.sqlMessage.includes("username")) {

                    console.log(err);

                    res.status(422);
                    res.type("json");
                    res.send(`{"Message":"The username provided already exists."}`);
                }

                // Duplicate entry error for the email 
                else if (err.sqlMessage.includes("email")) {

                    console.log(err);

                    res.status(422);
                    res.type("json");
                    res.send(`{"Message":"The email provided already exists."}`);
                }
            }

            else {

                console.log(err);

                res.status(500);
                res.type("json");
                res.send(`{"Message":"Internal Server Error"}`);
            }
        }

        else {

            res.status(201);
            res.type("json");
            res.send(`{"userid":"${results.insertId}"}`);
        }
    });
});


//ENDPOINT 3
//GET /user/:userid
//Get user by user id
app.get('/users/:userid', verifyToken, validateUser, function (req, res) {

    //retrieve user input
    var userid = req.params.userid;

    // Check if user is accessing their own data or is admin
    if (req.userid != userid && req.type !== 'Admin' && req.type !== 'admin') {
        return res.status(403).json({ message: 'Access denied' });
    }

    userDB.getUserByUserid(userid, function (err, results) {

        if (err) {

            console.log(err);

            res.status(500);
            res.type("json");
            res.send(`{"Message":"Internal Server Error"}`);
        }

        else {

            res.status(200);
            res.type("json");
            res.send(sanitizeResult(results));
        }
    });
});


//ENDPOINT 4
//POST /category
//Add a new category
app.post('/category', verifyToken, checkAdmin, validateCategory, function (req, res) {

    //retrieve category input
    var catname = req.body.catname;
    var cat_description = req.body.description;


    categoryDB.insertCategory(catname, cat_description, function (err, results) {

        if (err) {

            // Check for Duplication Entry
            if (err.code === "ER_DUP_ENTRY") {

                // Duplicate entry error for the category name 
                if (err.sqlMessage.includes("catname")) {

                    console.log(err);

                    res.status(422);
                    res.type("json");
                    res.send(`{"Message":"The category name provided already exists."}`);
                }
            }

            // Any other error
            else {

                console.log(err);

                res.status(500);
                res.type("json");
                res.send(`{"Message":"Internal Server Error"}`);
            }
        }

        else {

            res.status(201);
            res.type("json");
            res.send(`{"Message":"Rows affected:${results.affectedRows}"}`);

        }
    });
});


//ENDPOINT 5
//POST /platform
//Add a new platform
app.post('/platform', verifyToken, checkAdmin, validatePlatform, function (req, res) {

    //retrieve platform input
    var platform_name = req.body.platform_name;
    var platform_description = req.body.description;


    platformDB.insertPlatform(platform_name, platform_description, function (err, results) {

        if (err) {

            // Check for Duplication Entry
            if (err.code === "ER_DUP_ENTRY") {

                // Duplicate entry error for the platform name 
                if (err.sqlMessage.includes("platform_name")) {

                    console.log(err);

                    res.status(422);
                    res.type("json");
                    res.send(`{"Message":"The platform name provided already exists."}`);
                }
            }

            else {

                console.log(err);

                res.status(500);
                res.type("json");
                res.send(`{"Message":"Internal Server Error"}`);
            }
        }

        else {

            res.status(201);
            res.type("json");
            res.send(`{"Message":"Rows affected:${results.affectedRows}"}`);
        }
    });
});


//ENDPOINT 6
//POST /game
//Add a new game
app.post('/game', verifyToken, checkAdmin, upload.single('game_image'), function (req, res) {

    var title = req.body.title;
    var game_description = req.body.description;
    var price = req.body.price;
    var platformid = req.body.platformid;
    var categoryid = req.body.categoryid;
    var year = req.body.year;
    var game_image = req.file;
    console.log(price);

    // Validate game data
    if (!title || !game_description || !year || !price) {
        return res.status(400).json({ message: 'All game fields are required' });
    }

    gameDB.insertGame(title, game_description, year, game_image, function (err, results) {

        if (err) {

            console.log(err);
            res.status(500);
            res.type("json");
            res.send(`{"Message":"Internal Server Error"}`);
        }

        else {

            // Get the gameid
            var gameID = results.insertId;

            console.log(price);
            gameDB.insertGame_Platform(gameID, price, platformid, function (err) {

                if (err) {

                    console.log(err);
                    res.status(500);
                    res.type("json");
                    res.send(`{"Message":"Internal Server Error with game_platform"}`);
                }

                else {

                    gameDB.insertGame_Category(gameID, categoryid, function (err) {

                        if (err) {

                            console.log(err);
                            res.status(500);
                            res.type("json");
                            res.send(`{"Message":"Internal Server Error with game_category"}`);
                        }

                        else {

                            res.status(201);
                            res.type("json");
                            res.send(`{"Message":"gameid: ${gameID}"}`);
                        }
                    });
                }
            });
        }
    });
});


//ENDPOINT 7
//GET /game/:platform
//Get games based on platform name
app.get('/game_platform/:platform', function (req, res) {

    var platform_name = req.params.platform;

    // Sanitize platform name
    platform_name = platform_name.replace(/[<>'"\\;]/g, '').trim();

    platformDB.getGameByPlatformName(platform_name, function (err, results) {

        if (err) {

            console.log(err);

            res.status(500);
            res.type("json");
            res.send(`{"Message":"Internal Server Error"}`);
        }

        else {

            res.status(200);
            res.type("json");
            res.send(sanitizeResult(results));
        }
    });
});


//ENDPOINT 8
//DELETE /game/:id
//Delete a game
app.delete('/game/:id', verifyToken, checkAdmin, function (req, res) {

    var gameID = req.params.id;

    // Validate game ID
    if (!gameID || isNaN(gameID) || gameID <= 0) {
        return res.status(400).json({ message: 'Invalid game ID' });
    }

    gameDB.deleteGame(gameID, function (err, results) {

        if (err) {

            console.log(err);

            res.status(500);
            res.type("json");
            res.send(`{"Message":"Internal Server Error"}`);
        }

        else {

            res.status(204);
            res.type("json");
            res.send();
        }
    });
});


//ENDPOINT 10
//POST /user/:uid/game/:gid/review
//User add review to game
app.post('/users/:uid/game/:gid/review', verifyToken, validateReview, function (req, res) {

    var userid = req.params.uid;
    var gameID = req.params.gid;
    var content = req.body.content;  // Already sanitized by validateReview
    var rating = req.body.rating;

    // Check if user is posting for themselves
    if (req.userid != userid) {
        return res.status(403).json({ message: 'You can only post reviews for yourself' });
    }

    reviewDB.insertReview(userid, gameID, content, rating, function (err, results) {

        if (err) {

            console.log(err);

            res.status(500);
            res.type("json");
            res.send(`{"Message":"Internal Server Error"}`);
        }

        else {

            res.status(201);
            res.type("json");
            res.send(`{"reviewid":"${results.insertId}"}`);
        }
    });
});


//ENDPOINT 11
//GET /game/:id/review
//Get all reviews of a game
app.get('/game/:id/review', function (req, res) {

    var gameID = req.params.id;


    reviewDB.getReviewByGameID(gameID, function (err, results) {

        if (err) {

            console.log(err);

            res.status(500);
            res.type("json");
            res.send(`{"Message":"Internal Server Error"}`);
        }

        else {

            res.status(200);
            res.type("json");
            res.send(sanitizeResult(results));
        }
    });
});


//ENDPOINT 12
//GET /game/:id
//Get game
app.get('/game/:id', function (req, res) {

    var gameID = req.params.id;

    gameDB.getGameByGameID(gameID, function (err, results) {

        if (err) {

            res.status(500);
            res.type("json");
            res.send(`{"Message":"Internal Server Error"}`);
        }

        else {

            // Check if game exist
            if (results.length === 0) {

                res.status(404);
                res.type("json");
                res.send(`{"Message":"Game not found"}`);
            }

            else {

                res.status(200);
                res.type("json");
                res.send(sanitizeResult(results));
            }
        }
    });
});


//ENDPOINT 13
//GET /game
//Get all game
app.get('/game', function (req, res) {

    gameDB.getAllGame(function (err, results) {

        if (err) {

            console.log(err);

            res.status(500);
            res.type("json");
            res.send(`{"Message":"some error encounted!"}`);
        }

        else {

            res.status(200);
            res.type("json");
            res.send(sanitizeResult(results));
        }
    });
});

// ---------------------
// GLOBAL ERROR HANDLER - ADD THIS SECTION
// ---------------------
app.use((err, req, res, next) => {
    console.error(err.stack);
    
    // Don't leak error details in production
    if (process.env.NODE_ENV === 'production') {
        res.status(500).json({ 
            message: 'Internal Server Error' 
        });
    } else {
        res.status(500).json({ 
            message: err.message 
        });
    }
});

// 404 HANDLER - ADD THIS SECTION
app.use((req, res) => {
    res.status(404).json({ 
        message: 'Endpoint not found' 
    });
});

//---------------------

module.exports = app;