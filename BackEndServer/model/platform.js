/*
Summary: The platform.js is used create functions and what it does to the Platform database.
*/

const db = require('./databaseConfig');
var config = require('../config.js');
var jwt = require('jsonwebtoken');

var platformDB = {

    //Get all platform
    getAllPlat: function (callback) {
        var dbConn = db.getConnection();

        // Connect to MySQL DB
        dbConn.connect(function (err) {
            if (err) {

                return callback(err, null);
            }

            else {

                var getAllPlatSql = `SELECT * FROM platform`;

                dbConn.query(getAllPlatSql, [], function (err, results) {

                    if (err) {

                        dbConn.end();
                        return callback(err, null);
                    }

                    else {

                        dbConn.end();
                        return callback(null, results);
                    }
                });
            }
        });
    },

    //ENDPOINT 5
    //Add a new platform
    insertPlatform: function (platform_name, platform_description, callback) {

        var dbConn = db.getConnection();

        //connect to mysql db
        dbConn.connect(function (err) {

            if (err) {

                return callback(err, null);
            }

            else {

                var insertPlatSql = "insert into platform(platform_name, platform_description) values(?,?)";
                dbConn.query(insertPlatSql, [platform_name, platform_description], function (err, results) {

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


    //ENDPOINT 7
    //Get games based on platform name
    getGameByPlatformName: function (platform_name, callback) {

        var dbConn = db.getConnection();

        dbConn.connect(function (err) {

            if (err) {

                return callback(err, null);
            }

            else {

                var getGameByPlatNameSql = `SELECT g.gameID as gameid, g.title, g.game_description as description, 
                                            gp.price, p.platform_name as platform, c.catID as catid, c.catname, g.year, 
                                            DATE_FORMAT( g.created_at, '%Y-%m-%d %H:%i:%s') AS created_at
                                            FROM game g
                                            JOIN game_platform gp ON g.gameID = gp.fk_game
                                            JOIN game_category gc ON g.gameID = gc.fk_game
                                            JOIN platform p ON gp.fk_platform = p.platID
                                            JOIN category c ON gc.fk_category = c.catID
                                            WHERE p.platform_name = ?;`;

                dbConn.query(getGameByPlatNameSql, [platform_name], function (err, results) {

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

module.exports = platformDB;