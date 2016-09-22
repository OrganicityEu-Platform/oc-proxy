var config = require('./config'),
    fs = require('fs'),
    https = require('https'),
    ProxyStrategy = require('./controllers/proxyStrategy'),
    errorhandler = require('errorhandler');

var passport = require('passport');
var JwtBearerStrategy = require('passport-http-jwt-bearer').Strategy;
var indexOf = require('indexof-shim');

var cert = fs.readFileSync('cert.pem');

passport.use(new JwtBearerStrategy(
   cert,
   function(token, done) {
     done(null, {}, token);
   }
 ));

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
    res.header('Access-Control-Allow-Headers', 'origin, content-type, X-Auth-Token, Tenant-ID, Authorization, x-organicity-application, x-organicity-experiment');
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

app.post('/v2/entities', passport.authenticate('jwt-bearer', { session: false }), ProxyStrategy[config.pipeline].post);
app.get('/v2/entities/:assetId', passport.authenticate('jwt-bearer', { session: false }), ProxyStrategy[config.pipeline].get);
app.put('/v2/entities/:assetId', passport.authenticate('jwt-bearer', { session: false }), ProxyStrategy[config.pipeline].put);
app.delete('/v2/entities/:assetId', passport.authenticate('jwt-bearer', { session: false }), ProxyStrategy[config.pipeline].delete);

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
