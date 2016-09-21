var config = require('./config'),
    fs = require('fs'),
    https = require('https'),
    Root = require('./controllers/root').Root,
    errorhandler = require('errorhandler');

var passport = require('passport');
var JwtBearerStrategy = require('passport-http-jwt-bearer').Strategy;
var indexOf = require('indexof-shim');

var cert = fs.readFileSync('cert.pem');

passport.use(new JwtBearerStrategy(
   cert,
   function(token, done) {
	var user = {
		token: token
	};
     done(null, user, token);
   }
 ));

var rolehandler = function (roles) {
	return function(req, res, next) {
		for(var i = 0; i < roles.length; i++) {
			var role = roles[i];
			console.log('Check role: ', role);
			if(indexOf(req.user.token.realm_access.roles, role) >= 0) {
				req.headers['x-auth-subject'] = req.user.token.sub;
				next();
				return;
			}
		}
		res.status(403).send('You dont have to role to access this endpoint!');
	}
}

config.https = config.https || {};

var log = require('./lib/logger').logger.getLogger("Server");

var express = require('express');

/*
process.on('uncaughtException', function (err) {
  log.error('Caught exception: ' + err);
});
*/
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

var app = express();

//app.use(express.bodyParser());

app.use (function(req, res, next) {
    var bodyChunks = [];
    req.on('data', function(chunk) {
       bodyChunks.push(chunk);
    });

    req.on('end', function() {
        req.body = Buffer.concat(bodyChunks);
        next();
    });
});

app.use(errorhandler({log: log.error}))

app.use(function (req, res, next) {
    "use strict";
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', 'HEAD, POST, PUT, GET, OPTIONS, DELETE');
    res.header('Access-Control-Allow-Headers', 'origin, content-type, X-Auth-Token, Tenant-ID, Authorization');
    //log.debug("New Request: ", req.method);
    if (req.method == 'OPTIONS') {
        log.debug("CORS request");
        res.statusCode = 200;
        res.header('Content-Length', '0');
        res.send();
        res.end();
    }
    else {
        next();
    }
});

var port = config.port || 80;
if (config.https.enabled) port = config.https.port || 443;
app.set('port', port);

for (var p in config.public_paths) {
    log.debug('Public paths', config.public_paths[p]);
    app.all(config.public_paths[p], Root.public);
}

app.post('/*', passport.authenticate('jwt-bearer', { session: false }), rolehandler(['experimenter', 'participant']), Root.pep);
app.get('/*', passport.authenticate('jwt-bearer', { session: false }), rolehandler(['experimenter']), Root.pep);
app.put('/*', passport.authenticate('jwt-bearer', { session: false }), rolehandler(['experimenter']), Root.pep);
app.delete('/*', passport.authenticate('jwt-bearer', { session: false }), rolehandler(['experimenter']), Root.pep);

log.info('Starting OC proxy on port ' + port + '.');

if (config.https.enabled === true) {
    var options = {
        key: fs.readFileSync(config.https.key_file),
        cert: fs.readFileSync(config.https.cert_file)
    };

    https.createServer(options, function(req,res) {
        app.handle(req, res);
    }).listen(app.get('port'));
} else {
    app.listen(app.get('port'));
}
