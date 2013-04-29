(function() {
var mongodb = require('mongodb');

    var passport = require('passport');
    var LocalStrategy = require('passport-local').Strategy;
    
    var passwordHash = require("password-hash");
var flash = require('connect-flash');

    var NodeCache = require( "node-cache" );    
    var userCache = new NodeCache({ stdTTL: 100, checkperiod: 120});

    var settings = {
        mongoUrl: process.env.MONGOHQ_URL,
        baseUrl: process.env.SECURE_DOMAIN,
        userCollection: 'AdminUsers',
        hashOptions: {
            algorithm: "sha512"
        },
        maxAttempts: 3
    };


    var getUser = function(username, callback) {
        userCache.get(username, function(err, val) {
            if (val && val[username] !== undefined) return callback(val[username]);

            mongodb.Db.connect(settings.mongoUrl, function(error, client) {
            if(error) throw error;

            new mongodb.Collection(client, settings.userCollection).findOne({
                username: username
            }, function(err, user) {               
                client.close();
                userCache.set(username, user);
                return callback(user);
            });
        });

        })


    }


    passport.use(new LocalStrategy(

    function(username, password, done) {

        getUser(username, function(user) {
            if (!user) {
                return done(null, false, {
                            message: 'Invalid user/password'
                        });
            }

            user.loginAttempts = user.loginAttempts || [];
            var now = new Date().getTime();

            user.loginAttempts.push(now);

            if (user.loginAttempts.length > settings.maxAttempts) {
                var then = user.loginAttempts.shift();
                if (then > now - 60000) {
                     return done(null, false, {
                            message: 'Account locked'
                        });
                }
            }



            if (!passwordHash.isHashed(user.password)) {
            if (password != user.password) {
                return done(null, false, {
                            message: 'Invalid user/password'
                        });
            }

            }
            else {

            if (!passwordHash.verify(password, user.password)) {
                return done(null, false, {
                            message: 'Invalid user/password'
                        });
            }
}

            user.loginAttempts = [];
            return done(null, user);
        })    
    }));


    var ensureAuthenticated = function(req, res, next) {
            if(process.env.AUTHTYPE == "skip") {
                req.user = {
                    username: "skipped login"
                };
                return next();
            }
            if(req.isAuthenticated()) {
                return next();
            }

            req.session.callbackUrl = req.path;
            res.redirect(settings.baseUrl + '/login');
        }

    passport.serializeUser(function(user, done) {
        console.log(user);
        done(null, user.username);
    });

    passport.deserializeUser(function(id, done) {
        getUser(id, function(user) {
             return done(null, user);
        });
        console.log(id);
    });


    exports.configure = function(app, options) {

    app.use(passport.initialize());
    app.use(passport.session());
app.use(flash());

        var extend = require("extend");

        extend(settings, options);

        app.get('/logout', function(req, res) {
            req.logout();
            res.redirect(settings.baseUrl + '/');
        });

        app.get('/login', function(req, res) {
            res.render('login', {
                layout: "blanklayout",
                title: '',
                flash: req.flash()
            });
        });
   
        app.post('/login', passport.authenticate('local', {
            successRedirect: settings.baseUrl + '/loginredirect',
            failureRedirect: settings.baseUrl + '/login',
            failureFlash: true
        }));

        app.get("/loginredirect", function(req, res) {
            res.redirect(settings.baseUrl +( req.session.callbackUrl || "/"));
        })



    }


    exports.ensureAuthenticated = ensureAuthenticated;

    exports.addUser = function(username, password, roles) {
          mongodb.Db.connect(settings.mongoUrl, function(error, client) {
            if(error) throw error;
            var collection = new mongodb.Collection(client, settings.userCollection);
            collection.save({
                username: username,
                password: passwordHash.generate(password, settings.hashOptions),
                roles: roles || { admin: false }
            }, function() {               
                client.close();
            });
        });
    }

    exports.setPassword = function(username, password) {

       mongodb.Db.connect(settings.mongoUrl, function(error, client) {
            if(error) throw error;
            var collection = new mongodb.Collection(client, settings.userCollection);
            collection.findOne({
                username: username
            }, function(err, user) {
                if (user) {
                    user.password = passwordHash.generate(password, settings.hashOptions);
                     collection.save(user, function() {
                        client.close();
                        userCache.set(username, user);
                     });
                }else {
                       client.close();
                }
            });
        });
    }

    exports.setup = function() {
        // todo: copy setup code from chondric
        console.log("setup not implemented");
        return "";
    }

})();