/*


Summary: The review.js is used create functions and what it does to the Review database.
*/

const db = require('./databaseConfig');


var reviewDB = {

    //ENDPOINT 10
    //User add review to game
    insertReview: function (userid, gameID, content, rating, callback) {

        var dbConn = db.getConnection();

        //connect to mysql db
        dbConn.connect(function (err) {

            if (err) {

                return callback(err, null);
            }

            else {

                var insertReviewSql = `INSERT INTO review (fk_users, fk_games, content, rating) VALUES (?, ?, ?, ?);`
                dbConn.query(insertReviewSql, [userid, gameID, content, rating], function (err, results) {

                    if (err) {

                        dbConn.end();
                        return callback(err, null);
                    }

                    else {

                        dbConn.end();
                        return callback(err, results);
                    }
                })
            }
        });
    },


    //ENDPOINT 11
    //Get all reviews of a game
    getReviewByGameID: function (gameID, callback) {

        var dbConn = db.getConnection();

        dbConn.connect(function (err) {   

            if (err) {
                return callback(err, null);
            }

            else {   

                var getReviewByGameIDSql = `SELECT  r.fk_games AS gameid, r.content, r.rating, u.username, u.profile_pic_url, 
                                            DATE_FORMAT( r.created_at, '%Y-%m-%d %H:%i:%s') AS created_at
                                            FROM review r
                                            JOIN users u ON r.fk_users = u.userid
                                            WHERE r.fk_games = ?`;

                dbConn.query(getReviewByGameIDSql, [gameID], function (err, results) {

                    if (err) {

                        dbConn.end();
                        return callback(err, null);
                    }

                    else {

                        dbConn.end();
                        return callback(err, results);
                    }
                })
            }
        });
    }
}


module.exports = reviewDB;