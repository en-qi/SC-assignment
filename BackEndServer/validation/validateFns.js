// ============================================
// validateFns.js
// Input validation and output sanitization utilities
// ============================================

const validator = require('validator');
const xss = require('xss');

// ======================
// VALIDATION FUNCTIONS
// ======================

/**
 * Validate user registration input
 * Return response with status 400 if validation fails
 */
function validateRegister(req, res, next) {
    var username = req.body.username;
    var email = req.body.email;
    var password = req.body.password;

    // Username: alphanumeric only, 3-20 characters
    var usernamePattern = /^[a-zA-Z0-9]{3,20}$/;
    
    // Email: standard email format
    var emailPattern = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    
    // Password: at least 6 characters
    var passwordPattern = /^.{6,}$/;

    if (!username || !email || !password) {
        return res.status(400).json({ 
            message: 'All fields are required' 
        });
    }

    if (!usernamePattern.test(username)) {
        return res.status(400).json({ 
            message: 'Username must be 3-20 alphanumeric characters' 
        });
    }

    if (!emailPattern.test(email)) {
        return res.status(400).json({ 
            message: 'Invalid email format' 
        });
    }

    if (!passwordPattern.test(password)) {
        return res.status(400).json({ 
            message: 'Password must be at least 6 characters' 
        });
    }

    next();
}

/**
 * Validate user ID from req.params
 * Return response with status 400 if validation fails
 */
function validateUser(req, res, next) {
    var userid = req.params.userid || req.params.uid;

    if (!userid || isNaN(userid) || userid <= 0) {
        return res.status(400).json({ 
            message: 'Invalid User ID' 
        });
    }

    next();
}

/**
 * Validate user ID matches authenticated user (for authorization)
 */
function validateUserOwnership(req, res, next) {
    var paramUserid = req.params.userid || req.params.uid;
    var tokenUserid = req.userid; // From verifyToken middleware

    if (paramUserid !== tokenUserid) {
        return res.status(403).json({ 
            message: 'Access denied: User ID mismatch' 
        });
    }

    next();
}

/**
 * Validate game review content
 * Return response with status 400 if validation fails
 */
function validateReview(req, res, next) {
    var content = req.body.content;
    var rating = req.body.rating;

    // Content: allow alphanumeric, spaces, and basic punctuation
    var contentPattern = /^[a-zA-Z0-9\s.,!?'"()\-:;]{1,500}$/;
    
    // Rating: 1-5 only
    var ratingPattern = /^[1-5]$/;

    if (!content || !rating) {
        return res.status(400).json({ 
            message: 'Review content and rating are required' 
        });
    }

    if (!contentPattern.test(content.trim())) {
        return res.status(400).json({ 
            message: 'Review content contains invalid characters' 
        });
    }

    if (!ratingPattern.test(rating)) {
        return res.status(400).json({ 
            message: 'Rating must be between 1 and 5' 
        });
    }

    // Sanitize content before passing to next middleware
    req.body.content = sanitizeOutput(content);
    
    next();
}

/**
 * Validate game creation input
 */
function validateGame(req, res, next) {
    var title = req.body.title;
    var description = req.body.description;
    var year = req.body.year;
    var price = req.body.price;

    if (!title || !description || !year || !price) {
        return res.status(400).json({ 
            message: 'All game fields are required' 
        });
    }

    // Title: alphanumeric with spaces and basic punctuation
    var titlePattern = /^[a-zA-Z0-9\s.,!?'"()\-:;]{1,100}$/;
    
    // Year: valid year (1900-2100)
    var yearPattern = /^(19|20)\d{2}$/;
    
    // Price: comma-separated decimals
    var pricePattern = /^(\d+(\.\d{1,2})?)(,\d+(\.\d{1,2})?)*$/;

    if (!titlePattern.test(title.trim())) {
        return res.status(400).json({ 
            message: 'Invalid game title format' 
        });
    }

    if (!yearPattern.test(year)) {
        return res.status(400).json({ 
            message: 'Invalid year format (1900-2100)' 
        });
    }

    if (!pricePattern.test(price)) {
        return res.status(400).json({ 
            message: 'Invalid price format (e.g., 59.99,39.99)' 
        });
    }

    // Sanitize inputs
    req.body.title = sanitizeOutput(title);
    req.body.description = sanitizeOutput(description);
    
    next();
}

/**
 * Validate category creation input
 */
function validateCategory(req, res, next) {
    var catname = req.body.catname || req.body.name;
    var description = req.body.description;

    if (!catname) {
        return res.status(400).json({ 
            message: 'Category name is required' 
        });
    }

    // Category name: alphanumeric with spaces
    var catnamePattern = /^[a-zA-Z0-9\s\-]{1,50}$/;

    if (!catnamePattern.test(catname.trim())) {
        return res.status(400).json({ 
            message: 'Category name contains invalid characters' 
        });
    }

    if (description && description.length > 500) {
        return res.status(400).json({ 
            message: 'Description too long (max 500 chars)' 
        });
    }

    // Sanitize
    req.body.catname = sanitizeOutput(catname);
    if (description) req.body.description = sanitizeOutput(description);
    
    next();
}

/**
 * Validate platform creation input
 */
function validatePlatform(req, res, next) {
    var platform_name = req.body.platform_name || req.body.name;
    var description = req.body.description;

    if (!platform_name) {
        return res.status(400).json({ 
            message: 'Platform name is required' 
        });
    }

    // Platform name: alphanumeric with spaces and version numbers
    var platformPattern = /^[a-zA-Z0-9\s\-\.]{1,50}$/;

    if (!platformPattern.test(platform_name.trim())) {
        return res.status(400).json({ 
            message: 'Platform name contains invalid characters' 
        });
    }

    if (description && description.length > 500) {
        return res.status(400).json({ 
            message: 'Description too long (max 500 chars)' 
        });
    }

    // Sanitize
    req.body.platform_name = sanitizeOutput(platform_name);
    if (description) req.body.description = sanitizeOutput(description);
    
    next();
}

/**
 * Validate search input to prevent injection
 */
function validateSearch(req, res, next) {
    var input = req.body.input || '';
    var platform = req.body.platID || '';
    var category = req.body.catID || '';

    // Basic sanitization
    req.body.input = sanitizeSearchInput(input);
    req.body.platID = sanitizeSearchInput(platform);
    req.body.catID = sanitizeSearchInput(category);
    
    next();
}

// ======================
// SANITIZATION FUNCTIONS
// ======================

/**
 * Sanitize output to prevent XSS
 * Escapes HTML special characters
 */
function sanitizeOutput(text) {
    if (typeof text !== 'string') return text;
    
    // Use validator escape to convert <, >, &, ", ' to HTML entities
    return validator.escape(text.trim());
}

/**
 * Sanitize each record's values from database result
 */
function sanitizeResult(result) {
    if (!result) return result;
    
    // Handle array of results
    if (Array.isArray(result)) {
        return result.map(item => sanitizeRecord(item));
    }
    
    // Handle single object
    return sanitizeRecord(result);
}

/**
 * Sanitize a single database record
 */
function sanitizeRecord(record) {
    if (!record || typeof record !== 'object') return record;
    
    const sanitized = {};
    
    for (const [key, value] of Object.entries(record)) {
        if (typeof value === 'string') {
            sanitized[key] = sanitizeOutput(value);
        } else {
            sanitized[key] = value;
        }
    }
    
    return sanitized;
}

/**
 * Sanitize user input for search queries
 */
function sanitizeSearchInput(input) {
    if (!input || typeof input !== 'string') return '';
    
    // Remove potentially dangerous characters but keep search functionality
    return input.replace(/[<>'"\\;]/g, '').trim();
}

/**
 * Validate and sanitize login input
 */
function validateLogin(req, res, next) {
    var email = req.body.email;
    var password = req.body.password;

    if (!email || !password) {
        return res.status(400).json({ 
            message: 'Email and password are required' 
        });
    }

    // Basic email validation
    var emailPattern = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    
    if (!emailPattern.test(email)) {
        return res.status(400).json({ 
            message: 'Invalid email format' 
        });
    }

    // Sanitize
    req.body.email = validator.normalizeEmail(email);
    
    next();
}

// ======================
// ADMIN VALIDATION
// ======================

/**
 * Check if user is admin
 */
function checkAdmin(req, res, next) {
    if (req.type !== 'Admin' && req.type !== 'admin') {
        return res.status(403).json({ 
            message: 'Admin access required' 
        });
    }
    next();
}

/**
 * Validate game ID
 * Return response with status 400 if validation fails
 */
function validateGameID(req, res, next) {
    var gameID = req.params.gameID || req.params.id;
    
    if (!gameID || isNaN(gameID) || gameID <= 0) {
        return res.status(400).json({ 
            message: 'Invalid Game ID' 
        });
    }
    next();
}


// Validate user type/role
function validateUserType(req, res, next) {
    var type = req.body.type;
    var validTypes = ['User', 'Admin', 'Moderator'];
    
    if (type && !validTypes.includes(type)) {
        return res.status(400).json({ message: 'Invalid user type' });
    }
    
    // Prevent self-promotion to admin
    if (req.type !== 'Admin' && type === 'Admin') {
        return res.status(403).json({ message: 'Only admins can create admin accounts' });
    }
    next();
}

// Validate session
function validateSession(req, res, next) {
    if (!req.userid) {
        return res.status(401).json({ message: 'Authentication required' });
    }
    next();
}




// ======================
// EXPORTS
// ======================

module.exports = {
    // Validation functions
    validateRegister,
    validateUser,
    validateUserOwnership,
    validateReview,
    validateGame,
    validateCategory,
    validatePlatform,
    validateSearch,
    validateLogin,
    validateGameID,  // ← ADD THIS LINE
    
    // Authorization functions
    checkAdmin,
    
    // Sanitization functions
    sanitizeOutput,
    sanitizeResult,
    sanitizeRecord,
    sanitizeSearchInput
};