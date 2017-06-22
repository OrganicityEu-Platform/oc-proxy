process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

var config = require('./config');
var opbeat = undefined;

if(config.opbeat) {
  opbeat = require('opbeat').start(config.opbeat);
}

var fs = require('fs');
var https = require('https');
var ChainsOfResponsibility = require('./controllers/ChainsOfResponsibility');

config.https = config.https || {};

var log = require('./lib/logger').logger.getLogger("Server");

var express = require('express');
var app = express();

/*
process.on('uncaughtException', function (err) {
  log.error('Caught exception: ' + err);
});
*/

app.use (function(req, res, next) {
  console.log('Body handler!');
    var bodyChunks = [];
    req.on('data', function(chunk) {
       bodyChunks.push(chunk);
    });

    req.on('end', function() {
        req.body = Buffer.concat(bodyChunks);
        next();
    });
});

app.use(function (req, res, next) {
    "use strict";
  console.log('CORS handler!');
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

app.get('/', ChainsOfResponsibility[config.chain].status);
app.post('/v2/entities', ChainsOfResponsibility[config.chain].post);
app.get('/v2/entities/:assetId', ChainsOfResponsibility[config.chain].get);
app.post('/v2/entities/:assetId/attrs', ChainsOfResponsibility[config.chain].put);
app.delete('/v2/entities/:assetId', ChainsOfResponsibility[config.chain].delete);

if(config.opbeat) {
  console.log('Use Opbeat error logging');
  app.use(opbeat.middleware.express());
}

// Put a catch-all route handler as the very last route handler
app.use(function (req, res) {
  // If we reach this point it means that no prior route matched.
  // This means that we should render a "404 Not Found" page. Notice
  // that we do not call next() here as we don't want to forward the
  // request to the error handler below.

  // Send a 404 to the user
  res.status(404).send('404 - Page not found!')
});

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
