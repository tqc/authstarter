(function() {
    var mongodb = require('mongodb');
    var path = require("path");
    var fs = require("fs");
        var url = require("url");
    var express = require("express");

    var passport = require('passport');
    var LocalStrategy = require('passport-local').Strategy;

    var passwordHash = require("password-hash");
    var flash = require('connect-flash');

    var NodeCache = require("node-cache");
    var userCache = new NodeCache({
        stdTTL: 100,
        checkperiod: 120
    });

    var settings = {
        mongoUrl: process.env.MONGOHQ_URL,
        baseUrl: process.env.SECURE_DOMAIN || "",
        userCollection: process.env.USER_COLLECTION || 'AdminUsers',
        hashOptions: {
            algorithm: "sha512"
        },
        maxAttempts: 3,
        layout: "blanklayout",
        title: "Log In",
        customCss: ""
    };

    var dbServer, db;

    var ensureDbReady = function(callback) {
        if (db) return callback();
        var connectionUri = url.parse(settings.mongoUrl);
        var dbName = connectionUri.pathname.replace(/^\//, '');
        var dbUser = connectionUri.auth.split(":")[0];
        var dbPass = connectionUri.auth.split(":")[1];
        var dbopts = {
            auto_reconnect: true,
            poolSize: 5
        };

        dbServer = new mongodb.Server(connectionUri.hostname, parseInt(connectionUri.port, 10), dbopts);
        db = new mongodb.Db(dbName, dbServer, {});

        db.open(function(err, p_client) {
            if (err) throw err;
            db.authenticate(dbUser, dbPass, function(err, p_client) {
                if (err) throw err;
                console.log("Database opened");


                callback();
            });
        });

    };

    var getUser = function(username, callback) {
        userCache.get(username, function(err, val) {
            if (val && val[username] !== undefined) return callback(val[username]);

            ensureDbReady(function() {
                var collection = new mongodb.Collection(db, settings.userCollection);

                collection.findOne({
                    username: username
                }, function(err, user) {
                    if (err) throw err;
                    //                        client.close();
                    userCache.set(username, user);
                    return callback(user);
                });

            });
        });


    };


    passport.use(new LocalStrategy(

    function(username, password, done) {

        getUser(username, function(user) {
            if (!user) {
                return done(null, false, {
                    error: 'Invalid user/password'
                });
            }

            user.loginAttempts = user.loginAttempts || [];
            var now = new Date().getTime();

            user.loginAttempts.push(now);

            if (user.loginAttempts.length > settings.maxAttempts) {
                var then = user.loginAttempts.shift();
                if (then > now - 60000) {
                    return done(null, false, {
                        error: 'Account locked'
                    });
                }
            }



            if (!passwordHash.isHashed(user.password)) {
                if (password != user.password) {
                    return done(null, false, {
                        error: 'Invalid user/password'
                    });
                }

            } else {

                if (!passwordHash.verify(password, user.password)) {
                    return done(null, false, {
                        error: 'Invalid user/password'
                    });
                }
            }

            user.loginAttempts = [];
            return done(null, user);
        });
    }));



    passport.serializeUser(function(user, done) {
        //        console.log(user);
        done(null, user.username);
    });

    passport.deserializeUser(function(id, done) {
        getUser(id, function(user) {
            return done(null, user);
        });
        //        console.log(id);
    });


    exports.configure = function(app, options) {

        var ensureAuthenticated = function(req, res, next) {
            console.log(req.session);
            if (process.env.AUTHTYPE == "skip") {
                req.user = {
                    username: "skipped login"
                };
                return next();
            }
            if (req.isAuthenticated()) {
                return next();
            }

            req.session.callbackUrl = req.path;

            //            console.log (req.url);
            //  res.redirect(settings.baseUrl + '/login');

            res.locals({
                title: settings.title,
                customCss: settings.customCss,
                loginUrl: settings.baseUrl+"/login",
                flash: {
                    error: "Authentication Required"
                }
            });
            res.status(401);
            renderLogin(res);
        };


        app.use(passport.initialize());
        app.use(passport.session());
        app.use(flash());


        app.use(require('express-partials')());

        var extend = require("extend");
        extend(settings, options);

        //console.log(settings);

        if (options.db) {
            db = options.db;
        }
        ensureDbReady(function() {});

        app.use("/authstarter", express.static(__dirname + '/static'));

        if (!app.engines[".jshtml"]) {
            app.engine('jshtml', require("jshtml-express"));
        }


        var renderLogin = function(res) {
            var customviewpath = app.get("views");
            var defaultviewpath = __dirname + "/views/";
            var relative = path.relative(customviewpath, defaultviewpath);

            var view = __dirname + '/views/login.jshtml';
            var layout = __dirname + '/views/blanklayout.jshtml';

            if (fs.existsSync(customviewpath + "/login.jshtml")) view = customviewpath + "/login.jshtml";

            if (fs.existsSync(customviewpath + "/" + settings.layout + ".jshtml")) layout = customviewpath + "/" + settings.layout + ".jshtml";

            res.render(view, {
                layout: layout
            });

        };


        app.get('/logout', function(req, res) {
            req.logout();
            res.redirect(settings.baseUrl + '/');
        });

        app.get('/login', function(req, res) {

            res.locals({
                title: settings.title,
                customCss: settings.customCss,
                flash: req.flash(),
                loginUrl: settings.baseUrl+"/login",
                originalUrl: req.session.callbackUrl
            });

            renderLogin(res);

        });

        var authInternal = function(req, res, next) {
            //            console.log("auth for " + req.body.originalUrl);
            req.session.callbackUrl = req.body.originalUrl;
            return passport.authenticate('local', {
                successRedirect: settings.baseUrl + '/loginredirect',
                failureRedirect: settings.baseUrl + '/login',
                failureFlash: true
            })(req, res, next);

        };
        app.post('/login', authInternal);

        app.get("/loginredirect", function(req, res) {
            //            console.log("redirecting - original url is " + req.session.callbackUrl);
            res.redirect(req.session.callbackUrl || (settings.baseUrl + "/"));
        });


        exports.ensureAuthenticated = ensureAuthenticated;


    };


    exports.addUser = function(username, password, roles) {
        ensureDbReady(function() {
            db.open(function(error, client) {
                var collection = new mongodb.Collection(db, settings.userCollection);
                collection.save({
                    username: username,
                    password: passwordHash.generate(password, settings.hashOptions),
                    roles: roles || {
                        admin: false
                    }
                }, function() {
                    //                client.close();
                });
            });
        });
    };

    exports.setPassword = function(username, password) {
        ensureDbReady(function() {
            var collection = new mongodb.Collection(db, settings.userCollection);
            collection.findOne({
                username: username
            }, function(err, user) {
                if (user) {
                    user.password = passwordHash.generate(password, settings.hashOptions);
                    collection.save(user, function() {
                        client.close();
                        userCache.set(username, user);
                    });
                } else {
                    //          client.close();
                }
            });
        });
    };

    exports.setup = function() {
        // todo: copy setup code from chondric
        console.log("setup not implemented");
        return "";
    };

})();