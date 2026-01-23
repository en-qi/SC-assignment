require('dotenv').config();

var jwt = require('jsonwebtoken');
var config = require('../config');

function verifyToken(req, res, next) {
    var token = req.headers['authorization'];
    
    if (!token || !token.includes('Bearer')) {
        // Log failed token verification
        console.log('🔒 Token verification failed: No token or wrong format');
        res.status(403);
        return res.send({ auth: 'false', message: 'Not authorized!' });
    }
    else {
        token = token.split('Bearer ')[1];
        jwt.verify(token, process.env.JWT_SECRET || config.key, function (err, decoded) {
            if (err) {
                // Log invalid token
                console.log('🔒 Token verification failed: Invalid token', {
                    ip: req.ip,
                    url: req.url,
                    error: err.message
                });
                res.status(403);
                return res.send({ auth: false, message: 'Not authorized!' });
            }
            else {
                // Log successful authentication
                console.log('🔒 User authenticated:', {
                    userId: decoded.userid,
                    type: decoded.type,
                    ip: req.ip,
                    endpoint: req.url
                });
                
                req.userid = decoded.userid;
                req.type = decoded.type;
                next();
            }
        });
    }
}

module.exports = verifyToken;