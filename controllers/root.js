var config = require('./../config.js'),
    httpClient = require('./../lib/HTTPClient.js');

var log = require('./../lib/logger').logger.getLogger("Root");

var Root = (function() {

    var handleproxy = function(req, res, options, body){

      // Adds x-forwarded-for header
      options.headers = httpClient.getClientIp(req, req.headers);

      // Add OC header
      options.headers['x-organicity-foo'] = 'OC-FOO';

      // Handle body
      if(req.method === 'POST' && body) {
        console.log('Body:', body);
      }

      httpClient.sendData(options, body, res);
    }

    var pep = function(req, res) {

        var options = {
            protocol: 'http',
            host: config.app_host,
            port: config.app_port,
            path: req.url,
            method: req.method,
            headers: req.headers
        };

        var body = req.body.toString('utf8');

        handleproxy(req, res, options, body);
    };

    return {
        pep: pep
    }
})();

exports.Root = Root;
