#Auth Starter

This is the authentication code I find myself implementing on every project that needs a basic password protected demo or admin site. The flexibility of passport is nice, but for a simple app with few users all you need is something that works with minimal effort.

* Express 3
* Based on passport-local
* Username/password stored in mongodb
* Limit unsuccessful login attempts (3 per minute by default)
* Password hashing
* Users cached in memory to avoid excessive db requests
* Redirection to original url
* Hash preserved in redirection urls
* Default login form provided if not overridden by creating views/login.jshtml

The following routes are added to the app:
* GET /login
* POST /login
* GET /logout
* GET /loginredirect

## Installation

    npm install authstarter

To create necessary auth related view files, run

    node
    require("authstarter").setup();

## Usage

    var partials = require('express-partials');
    var AuthStarter = require("authstarter");

    var app = express();

    app.use(partials());

    app.configure(function() {
        app.use(express.cookieParser());
        app.use(express.session({
            secret: 'secret'
        }));
        app.use(express.bodyParser());
    
        AuthStarter.configure(app);
        app.use(app.router);
        app.use(express.static(__dirname + '/static'));
        app.engine('jshtml', require('jshtml-express'));
        app.set('view engine', 'jshtml');
    });


    app.get('/', AuthStarter.ensureAuthenticated, function(req, res) {
        req.send('Secured content');
    });


## User setup

The user store is a mongodb collection containing documents like:

    {
      _id: ObjectId("537159a186915c696a000521"),
      username: "username",
      password: "password",
      roles: {
        admin: false
      }
    }

Passwords may be either plain text or hashed in the format used by https://github.com/davidwood/node-password-hash

Users may be created manually or using one of the provided functions that include password hashing.

    AuthStarter.addUser("username", "password", {"user": true, "admin":false});

    AuthStarter.setPassword(username, password);

## Options

	var settings = {
        mongoUrl: process.env.MONGOHQ_URL,
        baseUrl: process.env.SECURE_DOMAIN,
        userCollection: process.env.USER_COLLECTION || 'AdminUsers',
        hashOptions: {
            algorithm: "sha512"
        },
        maxAttempts: 3,
        layout: "blanklayout",
        title: "Log In",
        customCss: ""
    };

    AuthStarter.configure(app, settings);

* mongoUrl - a mongodb url as used by mongo-native
* baseUrl - used to make redirects absolute. eg "https://example.com"
* userCollection - name of the mongodb collection
* hashOptions - as used by password-hash
* maxAttempts - number of incorrect login attempts allowed within one minute






