/*


Summary: The category.js is used create functions and what it does to the Category database.
*/

const db = require('./databaseConfig');
var config = require('../config.js');
var jwt = require('jsonwebtoken');

var categoryDB = {


    //ENDPOINT 4
    //Add a new category
    insertCategory: function (catname, cat_description, callback) {

        var dbConn = db.getConnection();

        //connect to mysql db
        dbConn.connect(function (err) {

            if (err) {

                return callback(err, null);
            }

            else {

                var insertCatSql = "insert into category(catname, cat_description) values(?,?)";
                dbConn.query(insertCatSql, [catname, cat_description], function (err, results) {

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


    //Get all category
    getAllCat: function (callback) {
        var dbConn = db.getConnection();

        // Connect to MySQL DB
        dbConn.connect(function (err) {
            if (err) {

                return callback(err, null);
            }

            else {

                var getAllCatSql = `SELECT * FROM category`;

                dbConn.query(getAllCatSql, [], function (err, results) {

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

}

module.exports = categoryDB;