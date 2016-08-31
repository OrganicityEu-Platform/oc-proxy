var config = require('./../config.js'),
    httpClient = require('./../lib/HTTPClient.js');

var log = require('./../lib/logger').logger.getLogger("Root");

var Root = (function() {

    var callPoxy = function(req, res, options, body){

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

    // Is experiment allowed to feed data
    var call1 = function(req, res, options, body) {
      call2(req, res, options, body);
    };

    // Is Experimenter of Experiment
    var call2 = function(req, res, options, body) {
      call3(req, res, options, body);
    };

    // Is Application of Experiment
    var call3 = function(req, res, options, body) {
      call4(req, res, options, body);
    };

    // Does the experiment have quota
    var call4 = function(req, res, options, body) {
      call5(req, res, options, body);
    };

    // Parse body
    var call5 = function(req, res, options, body) {
      callPoxy(req, res, options, body);
    };

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

      call1(req, res, options, body);

    };

    return {
        pep: pep
    }
})();

exports.Root = Root;
