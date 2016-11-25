var config = require('./config'),
    fs = require('fs'),
    https = require('https'),
    ChainsOfResponsibility = require('./controllers/ChainsOfResponsibility'),
    errorhandler = require('errorhandler');

config.https = config.https || {};

var log = require('./lib/logger').logger.getLogger("Server");

var express = require('express');

if(config.opbeat) {
  var opbeat = require('opbeat').start(config.opbeat);
}

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

app.post('/v2/entities', ChainsOfResponsibility[config.chain].post);
app.get('/v2/entities/:assetId', ChainsOfResponsibility[config.chain].get);
app.post('/v2/entities/:assetId/attrs', ChainsOfResponsibility[config.chain].put);
app.delete('/v2/entities/:assetId', ChainsOfResponsibility[config.chain].delete);

if(config.opbeat) {
  app.use(opbeat.middleware.express());
}

app.use(errorhandler({log: log.error}))

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
