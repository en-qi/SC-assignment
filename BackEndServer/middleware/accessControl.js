const userDB = require('../model/users');
const gameDB = require('../model/game');

module.exports = {
    // Check if user can modify a review
    canModifyReview: function(req, res, next) {
        var reviewID = req.params.reviewID;
        var userid = req.userid;
        
        if (!reviewID) return res.status(400).json({ message: 'Review ID required' });
        
        // Check if review exists and user owns it
        var dbConn = require('./databaseConfig').getConnection();
        dbConn.connect(function(err) {
            if (err) return res.status(500).json({ message: 'Database error' });
            
            var sql = 'SELECT fk_users FROM review WHERE reviewID = ?';
            dbConn.query(sql, [reviewID], function(err, results) {
                dbConn.end();
                if (err) return res.status(500).json({ message: 'Database error' });
                if (results.length === 0) return res.status(404).json({ message: 'Review not found' });
                
                var reviewOwner = results[0].fk_users;
                if (reviewOwner != userid && req.type !== 'Admin') {
                    return res.status(403).json({ message: 'Cannot modify other users reviews' });
                }
                next();
            });
        });
    },
    
    // Check if user can delete content
    canDeleteContent: function(contentType) {
        return function(req, res, next) {
            if (req.type === 'Admin') return next();
            
            var contentID = req.params.id;
            var userid = req.userid;
            
            var tableMap = {
                'review': 'review',
                'game': 'game',
                'comment': 'comments'
            };
            
            var table = tableMap[contentType];
            if (!table) return res.status(400).json({ message: 'Invalid content type' });
            
            var dbConn = require('./databaseConfig').getConnection();
            dbConn.connect(function(err) {
                if (err) return res.status(500).json({ message: 'Database error' });
                
                var sql = `SELECT created_by FROM ${table} WHERE ${contentType}ID = ?`;
                dbConn.query(sql, [contentID], function(err, results) {
                    dbConn.end();
                    if (err) return res.status(500).json({ message: 'Database error' });
                    if (results.length === 0) return res.status(404).json({ message: 'Content not found' });
                    
                    if (results[0].created_by != userid) {
                        return res.status(403).json({ message: 'Cannot delete other users content' });
                    }
                    next();
                });
            });
        };
    }
};