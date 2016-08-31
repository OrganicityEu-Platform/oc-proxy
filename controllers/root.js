var config = require('./../config.js'),
    proxy = require('./../lib/HTTPClient.js'),
    IDM = require('./../lib/idm.js').IDM,
    AZF = require('./../lib/azf.js').AZF;

var log = require('./../lib/logger').logger.getLogger("Root");

var Root = (function() {

    var pep = function(req, res) {

        var body = req.body.toString('utf8');

        var options = {
            protocol: 'http',
            host: config.app_host,
            port: config.app_port,
            path: req.url,
            method: req.method,
            headers: proxy.getClientIp(req, req.headers)
        };

        // Add header
        options.headers['x-organicity-foo'] = 'OC-FOO';

        // Handle body
        if(req.method === 'POST' && body) {
          console.log('Body:', body);
        }

        proxy.sendData(options, body, res);
        return;

    };

    return {
        pep: pep
    }
})();

exports.Root = Root;
