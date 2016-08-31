var config = require('./../config.js'),
    httpClient = require('./../lib/HTTPClient.js');

var log = require('./../lib/logger').logger.getLogger("Root");

var Root = (function() {

    // Is experiment allowed to feed data
    var call1 = function(req, res, options, body) {

      var optionsCall = {
          protocol: 'http',
          host: 'pro.server.organicity.eu',
          port: '80',
          path: '/',
          method: 'GET'
      };

      httpClient.sendData(optionsCall, undefined, res, function(status, responseText, headers) {
        options.headers['X-organicity-call1'] = 'OKAY';
        call2(req, res, options);
      });
    };

    // Is Participant/Experimenter of Experiment
    var call2 = function(req, res, options, body) {

      var optionsCall = {
          protocol: 'http',
          host: 'pro.server.organicity.eu',
          port: '80',
          path: '/',
          method: 'GET'
      };

      httpClient.sendData(optionsCall, undefined, res, function(status, responseText, headers) {
        options.headers['X-organicity-call2'] = 'OKAY';
        call3(req, res, options);
      });

    };

    // Is Application of Experiment
    var call3 = function(req, res, options, body) {
      var optionsCall = {
          protocol: 'http',
          host: 'pro.server.organicity.eu',
          port: '80',
          path: '/',
          method: 'GET'
      };

      httpClient.sendData(optionsCall, undefined, res, function(status, responseText, headers) {
        options.headers['X-organicity-call3'] = 'OKAY';
        call4(req, res, options);
      });

    };

    // Does the experiment have quota
    var call4 = function(req, res, options, body) {
      var optionsCall = {
          protocol: 'http',
          host: 'pro.server.organicity.eu',
          port: '80',
          path: '/',
          method: 'GET'
      };

      httpClient.sendData(optionsCall, undefined, res, function(status, responseText, headers) {
        options.headers['X-organicity-call4'] = 'OKAY';
        call5(req, res, options);
      });
    };

    // Check the validity of the asset
    var call5 = function(req, res, options, body) {

      // Handle body
      if(req.method === 'POST' && body) {
        console.log('Body:', body);
      }

      call6(req, res, options, body);
    };

    // Call the configured server
    var call6 = function(req, res, options, body){
      // Add x-forwarded-for header
      options.headers = httpClient.getClientIp(req, req.headers);
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

      call1(req, res, options, body);
    };

    return {
        pep: pep
    }
})();

exports.Root = Root;
