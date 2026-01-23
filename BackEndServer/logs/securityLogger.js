// logs/securityLogger.js - Simple security event logger
const fs = require('fs');
const path = require('path');

const logDir = path.join(__dirname, '..', 'logs');
if (!fs.existsSync(logDir)) {
    fs.mkdirSync(logDir, { recursive: true });
}

const securityLogStream = fs.createWriteStream(
    path.join(logDir, 'security-events.log'),
    { flags: 'a' }
);

module.exports = {
    logSecurityEvent: function(eventType, details = {}) {
        const logEntry = {
            timestamp: new Date().toISOString(),
            event: eventType,
            ...details
        };
        
        // Remove sensitive data
        if (logEntry.password) delete logEntry.password;
        if (logEntry.token) delete logEntry.token;
        
        securityLogStream.write(JSON.stringify(logEntry) + '\n');
        
        // Console log for development
        if (process.env.NODE_ENV !== 'production') {
            console.log(`🔒 SECURITY: ${eventType}`, details);
        }
    }
};