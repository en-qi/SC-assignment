// middleware/auditLogger.js
const fs = require('fs');
const path = require('path');

const logDir = path.join(__dirname, '..', 'logs');
if (!fs.existsSync(logDir)) {
    fs.mkdirSync(logDir, { recursive: true });
}

const auditLogStream = fs.createWriteStream(
    path.join(logDir, 'audit-trail.log'),
    { flags: 'a' }
);

module.exports = function auditLogger(req, res, next) {
    const startTime = Date.now();
    
    // Log when response finishes
    res.on('finish', function() {
        const duration = Date.now() - startTime;
        
        const auditEntry = {
            timestamp: new Date().toISOString(),
            method: req.method,
            url: req.url,
            statusCode: res.statusCode,
            duration: `${duration}ms`,
            ip: req.ip || req.connection.remoteAddress,
            userId: req.userid || 'anonymous',
            userAgent: req.get('User-Agent') || 'unknown'
        };
        
        // Don't log passwords or tokens
        if (req.body) {
            const safeBody = { ...req.body };
            if (safeBody.password) safeBody.password = '[REDACTED]';
            if (safeBody.token) safeBody.token = '[REDACTED]';
            auditEntry.requestBody = safeBody;
        }
        
        auditLogStream.write(JSON.stringify(auditEntry) + '\n');
    });
    
    next();
};