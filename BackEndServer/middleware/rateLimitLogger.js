// middleware/rateLimitLogger.js
const { logSecurityEvent, SecurityEvents } = require('../logs/securityLogger');

module.exports = function rateLimitLogger(req, res, next) {
    const ip = req.ip;
    const path = req.path;
    const method = req.method;
    
    // Track request frequency (simple implementation)
    const requestTracker = new Map();
    const WINDOW_MS = 60000; // 1 minute
    const MAX_REQUESTS = 100;
    
    const key = `${ip}:${path}:${method}`;
    const now = Date.now();
    
    if (!requestTracker.has(key)) {
        requestTracker.set(key, { count: 1, startTime: now });
    } else {
        const tracker = requestTracker.get(key);
        
        // Reset if window passed
        if (now - tracker.startTime > WINDOW_MS) {
            tracker.count = 1;
            tracker.startTime = now;
        } else {
            tracker.count++;
            
            // Log if approaching limit
            if (tracker.count > MAX_REQUESTS * 0.8) {
                logSecurityEvent(SecurityEvents.RATE_LIMIT_EXCEEDED, {
                    ip,
                    path,
                    method,
                    count: tracker.count,
                    limit: MAX_REQUESTS,
                    userId: req.userid || 'anonymous'
                });
            }
        }
    }
    
    // Cleanup old trackers
    setTimeout(() => {
        for (const [trackKey, value] of requestTracker.entries()) {
            if (now - value.startTime > WINDOW_MS * 2) {
                requestTracker.delete(trackKey);
            }
        }
    }, WINDOW_MS * 2);
    
    next();
};