/*


Summary: The game.js is used create functions and what it does to the games.
*/

const db = require('./databaseConfig');


var gameDB = {


    getSearchGameDetail: function (gameID, callback) {

        var dbConn = db.getConnection();

        dbConn.connect(function (err) {

            if (err) {

                return callback(err, null);
            }

            else {

                var getGameInfoSql = `SELECT g.gameID, g.title, g.game_image, g.year, g.game_description,
                                            GROUP_CONCAT(DISTINCT platform_name) AS platforms,
                                            GROUP_CONCAT(DISTINCT catname) AS categories,
                                            GROUP_CONCAT(DISTINCT price) AS prices
                                        FROM sp_games.game g
                                        JOIN game_platform gp ON g.gameID = gp.fk_game
                                        JOIN sp_games.platform p ON gp.fk_platform = p.platID
                                        JOIN game_category gc ON g.gameID = gc.fk_game
                                        JOIN sp_games.category c ON gc.fk_category = c.catID
                                        WHERE gameID = ?
                                        GROUP BY g.gameID, g.title`;

                dbConn.query(getGameInfoSql, [gameID], function (err, results) {

                    if (err) {

                        dbConn.end();
                        return callback(err, null);
                    }

                    else {

                        dbConn.end();

                        // Convert longblob to base64
                        results.forEach((result) => {
                            const imageBuffer = result.game_image;
                            const base64Image = imageBuffer.toString('base64');
                            result.game_image = base64Image;
                        });

                        return callback(err, results);
                    }
                });
            }
        });
    },


    //Get game from search bar
    getSearchGame: function (input, platform, category, callback) {

        var dbConn = db.getConnection();

        dbConn.connect(function (err) {

            if (err) {
                
                return callback(err, null);
            }

            else {

                if (category) {

                    var getSearchSql = `SELECT gameID, title, game_image, platform_name, price FROM sp_games.game g 
                                        JOIN game_platform gp ON g.gameID = gp.fk_game 
                                        JOIN sp_games.platform p ON gp.fk_platform = p.platID
                                        JOIN game_category gc ON g.gameID = gc.fk_game
                                        JOIN sp_games.category c ON gc.fk_category = c.catID
                                        WHERE title LIKE ?`

                    searchFilterArr = [`%${input}%`];

                    getSearchSql += ' AND catname = ?';
                    searchFilterArr.push(category);

                    if (platform) {

                        getSearchSql += " AND platform_name = ?";
                        searchFilterArr.push(platform);
                    }
                }

                else {

                    var getSearchSql = `SELECT gameID, title, game_image, platform_name, price FROM sp_games.game g 
                                        JOIN game_platform gp ON g.gameID = gp.fk_game 
                                        JOIN sp_games.platform p ON gp.fk_platform = p.platID
                                        WHERE title LIKE ?`

                    searchFilterArr = [`%${input}%`];

                    if (platform) {

                        getSearchSql += " AND platform_name = ?";
                        searchFilterArr.push(platform);
                    }
                }


                dbConn.query(getSearchSql, searchFilterArr, function (err, results) {

                    if (err) {

                        dbConn.end();
                        return callback(err, null);
                    }

                    else {

                        dbConn.end();

                        // Convert longblob to base64
                        results.forEach((result) => {
                            const imageBuffer = result.game_image;
                            const base64Image = imageBuffer.toString('base64');
                            result.game_image = base64Image;
                        });

                        return callback(err, results);
                    }

                })
            }
        });
    },

    // Endpoint 6 
    // Add new game into game table
    insertGame: function (title, game_description, year, game_image, callback) {

        var dbConn = db.getConnection();

        //connect to mysql db
        dbConn.connect(function (err) {
            if (err) {

                return callback(err, null);
            }

            else {

                var insertGameSql = `INSERT INTO game (title, game_description, year, game_image) VALUES ('${title}', '${game_description}', '${year}', ?);`;
                dbConn.query(insertGameSql, [game_image.buffer], function (err, results) {

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

    // Add new platform id and price of game
    insertGame_Platform: function (gameID, price, platformid, callback) {

        var dbConn = db.getConnection();

        dbConn.connect(function (err) {

            if (err) {

                return callback(err, null);
            }

            else {

                // Split the platform id and price into an array
                var priceArr = price.split(',');
                var platformArr = platformid.split(',');

                for (var i = 0; i < platformArr.length; i++) {

                    var newprice = priceArr[i];
                    var newplatformid = platformArr[i];


                    var insertGamePlatSql = "INSERT INTO game_platform (fk_game, fk_platform, price) VALUES (?, ?, ?)";
                    dbConn.query(insertGamePlatSql, [gameID, newplatformid, newprice], function (err, results) {

                        if (err) {

                            dbConn.end();
                            return callback(err, null);
                        }
                    });
                }

                dbConn.end();
                return callback(null);
            }
        });
    },

    // Add new category id of game
    insertGame_Category: function (gameID, categoryid, callback) {

        var dbConn = db.getConnection();

        dbConn.connect(function (err) {

            if (err) {

                return callback(err, null);
            }

            else {

                var categoryArr = categoryid.split(',');

                for (var i = 0; i < categoryArr.length; i++) {

                    var newcategoryid = categoryArr[i];

                    var insertGameCatSql = "INSERT INTO game_category (fk_game, fk_category) VALUES (?, ?)";
                    dbConn.query(insertGameCatSql, [gameID, newcategoryid], function (err, results) {

                        if (err) {

                            dbConn.end();
                            return callback(err, null);
                        }
                    });
                }

                dbConn.end();
                return callback(null);
            }
        });
    },


    // ENDPOINT 8
    // Delete a game
    deleteGame: function (gameID, callback) {

        var dbConn = db.getConnection();

        dbConn.connect(function (err) {

            if (err) {

                return callback(err, null);
            }

            else {
                var deleteGameSql = "DELETE FROM game WHERE gameID=?";
                dbConn.query(deleteGameSql, [gameID], function (err, gameResults) {

                    if (err) {

                        dbConn.end();
                        return callback(err, null);
                    }

                    else {

                        dbConn.end();
                        return callback(null, gameResults);
                    }
                });
            }
        });
    },


    // Endpoint 9
    // Update a game
    updateGame: function (title, game_description, year, game_image, gameID, callback) {

        var dbConn = db.getConnection();

        dbConn.connect(function (err) {

            if (err) {
                return callback(err, null);
            }

            else {

                var updateGameSql = `update game set title='${title}', game_description='${game_description}', year='${year}', game_image='${game_image.buffer}' where gameID='${gameID}`;
                dbConn.query(updateGameSql, [], function (err, results) {

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

    // Get the ID for game platform
    get_Plat_ID: function (gameID, callback) {

        var dbConn = db.getConnection();

        dbConn.connect(function (err) {

            if (err) {

                return callback(err, null);
            }

            else {

                var getPlatIDSql = "SELECT game_platformID FROM game_platform WHERE fk_game=?";
                dbConn.query(getPlatIDSql, [gameID], function (err, results) {

                    if (err) {

                        dbConn.end();
                        return callback(err, null);
                    }

                    else {

                        // Put into an array
                        var Plat_IDs = [];
                        for (var i = 0; i < results.length; i++) {

                            Plat_IDs.push(results[i].game_platformID);
                        }

                        dbConn.end();
                        return callback(null, Plat_IDs);
                    }
                });
            }
        });
    },

    // Get the ID for game category
    get_Cat_ID: function (gameID, callback) {

        var dbConn = db.getConnection();

        dbConn.connect(function (err) {

            if (err) {

                return callback(err, null);
            }

            else {
                var getCatIDSql = "SELECT game_categoryID FROM game_category WHERE fk_game=?";
                dbConn.query(getCatIDSql, [gameID], function (err, results) {

                    if (err) {

                        dbConn.end();
                        return callback(err, null);
                    }

                    else {

                        // Put into an array
                        var Cat_IDs = [];
                        for (var i = 0; i < results.length; i++) {

                            Cat_IDs.push(results[i].game_categoryID);
                        }

                        dbConn.end();
                        return callback(null, Cat_IDs);
                    }
                });
            }
        });
    },

    // Update platform id and price of game
    updatePlatform: function (gameID, platformid, price, Plat_IDs, callback) {

        var dbConn = db.getConnection();

        dbConn.connect(function (err) {

            if (err) {

                return callback(err, null);
            }

            var priceArr = price.split(',');
            var platformArr = platformid.split(',');

            var updateSql = "UPDATE game_platform SET fk_platform=?, price=? WHERE game_platformID=?";
            var deleteSql = "DELETE FROM game_platform WHERE game_platformID=?";
            var postSql = "INSERT INTO game_platform (fk_game, fk_platform, price) VALUES (?, ?, ?)";

            // Compare number of platform IDs in request to number of existing platform IDs in database
            if (platformArr.length === Plat_IDs.length) {

                // Update existing platform IDs and price
                for (var i = 0; i < Plat_IDs.length; i++) {

                    dbConn.query(updateSql, [platformArr[i], priceArr[i], Plat_IDs[i]], function (err, results) {

                        if (err) {

                            dbConn.end();
                            return callback(err, results);
                        }
                    });
                }
            }

            else if (platformArr.length < Plat_IDs.length) {

                // Update then Delete extra platform IDs and price
                for (var i = 0; i < Plat_IDs.length; i++) {

                    if (i < platformArr.length) {

                        dbConn.query(updateSql, [platformArr[i], priceArr[i], Plat_IDs[i]], function (err, results) {

                            if (err) {

                                dbConn.end();
                                return callback(err, results);
                            }
                        });
                    }

                    else {

                        dbConn.query(deleteSql, [Plat_IDs[i]], function (err, results) {

                            if (err) {

                                dbConn.end();
                                return callback(err, results);
                            }
                        });
                    }
                }
            }

            else if (platformArr.length > Plat_IDs.length) {

                // Update then Add new platform IDs and price
                for (var i = 0; i < platformArr.length; i++) {

                    if (i < Plat_IDs.length) {

                        dbConn.query(updateSql, [platformArr[i], priceArr[i], Plat_IDs[i]], function (err, results) {

                            if (err) {

                                dbConn.end();
                                return callback(err, results);
                            }
                        });
                    }

                    else {

                        dbConn.query(postSql, [gameID, platformArr[i], priceArr[i]], function (err, results) {

                            if (err) {

                                dbConn.end();
                                return callback(err, results);
                            }
                        });
                    }
                }
            }

            dbConn.end();
            return callback(null);
        });
    },

    // Update category id of game
    updateCategory: function (gameID, categoryid, Cat_IDs, callback) {

        var dbConn = db.getConnection();

        dbConn.connect(function (err) {

            if (err) {

                return callback(err, null);
            }

            var categoryArr = categoryid.split(',');

            var updateSql = "UPDATE game_category SET fk_category=? WHERE game_categoryID=?";
            var deleteSql = "DELETE FROM game_category WHERE game_categoryID=?";
            var postSql = "INSERT INTO game_category (fk_game, fk_category) VALUES (?, ?)";

            // Compare number of Category IDs in request to number of existing Category IDs in database
            if (categoryArr.length === Cat_IDs.length) {

                // Update existing Category IDs
                for (var i = 0; i < Cat_IDs.length; i++) {

                    dbConn.query(updateSql, [categoryArr[i], Cat_IDs[i]], function (err, results) {

                        if (err) {

                            dbConn.end();
                            return callback(err, results);
                        }
                    });
                }
            }

            else if (categoryArr.length < Cat_IDs.length) {

                // Update then Delete extra Category IDs
                for (var i = 0; i < Cat_IDs.length; i++) {

                    if (i < categoryArr.length) {

                        dbConn.query(updateSql, [categoryArr[i], Cat_IDs[i]], function (err, results) {

                            if (err) {

                                dbConn.end();
                                return callback(err, results);
                            }
                        });
                    }

                    else {

                        dbConn.query(deleteSql, [Cat_IDs[i]], function (err, results) {

                            if (err) {

                                dbConn.end();
                                return callback(err, results);
                            }
                        });
                    }
                }
            }

            else if (categoryArr.length > Cat_IDs.length) {

                // Update then Add new Category IDs
                for (var i = 0; i < categoryArr.length; i++) {

                    if (i < Cat_IDs.length) {

                        dbConn.query(updateSql, [categoryArr[i], Cat_IDs[i]], function (err, results) {

                            if (err) {

                                dbConn.end();
                                return callback(err, results);
                            }
                        });
                    }

                    else {

                        dbConn.query(postSql, [gameID, categoryArr[i]], function (err, results) {

                            if (err) {

                                dbConn.end();
                                return callback(err, results);
                            }
                        });
                    }
                }
            }

            dbConn.end();
            return callback(null);
        });
    },


    // ENDPOINT 12
    // Get a game
    getGameByGameID: function (gameID, callback) {

        var dbConn = db.getConnection();

        dbConn.connect(function (err) {

            if (err) {

                return callback(err, null);
            }

            else {

                var getGameByIDSql = `select gameID, title, game_description, game_image, year,
                                        DATE_FORMAT(created_at, '%Y-%m-%d %H:%i:%s') AS created_at 
                                        FROM game where gameID = ?`;

                dbConn.query(getGameByIDSql, [gameID], function (err, results) {

                    if (err) {

                        dbConn.end();
                        return callback(err, null);
                    }

                    else {

                        dbConn.end();
                        return callback(err, results);
                    }

                });
            }

        });
    },


    // ENDPOINT 13
    // Get all game
    getAllGame: function (callback) {

        var dbConn = db.getConnection();

        dbConn.connect(function (err) {

            if (err) {
                return callback(err, null);
            }

            else {

                var getGameSql = `select gameID, title, game_description, game_image, year,
                                    DATE_FORMAT(created_at, '%Y-%m-%d %H:%i:%s') AS created_at 
                                    FROM game`;

                dbConn.query(getGameSql, [], function (err, results) {

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


module.exports = gameDB;