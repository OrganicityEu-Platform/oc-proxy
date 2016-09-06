var config = require('./../config.js'),
    httpClient = require('./../lib/HTTPClient.js');

var log = require('./../lib/logger').logger.getLogger("Root");

if (!Number.isInteger) {
  Number.isInteger = function isInteger (nVal) {
    return typeof nVal === "number" && isFinite(nVal) && nVal > -9007199254740992 && nVal < 9007199254740992 && Math.floor(nVal) === nVal;
  };
}

var Root = (function() {

	var appid = 0;
	var expid = 0;
	var sub = undefined;

	var headerExists = function (headers, name, res) {
		if(!headers[name]) {
			res.statusCode = 400;
			res.send('HTTP header ' + name.toLowerCase() + ' not provided!');
			return false; 
		}
		return true;
	}

	var errorHandler = function(res) {
		return function(status, resp) {
		    log.error('HTTP error. Status: ', status, 'Response: ', resp);
		    res.statusCode = status;
		    res.send(resp);
		}
	}

    // Check HTTP headers
    var call0 = function(req, res, options, body) {

		//#################################################################
		// Check, if some headers do exist
		//#################################################################

		if(!headerExists(options.headers, 'x-organicity-application', res)) {
			return;
		}

		if(!headerExists(options.headers, 'x-organicity-experiment', res)) {
			return;
		}

		if(!headerExists(options.headers, 'x-auth-subject', res)) {
			return;
		}

		if(!headerExists(options.headers, 'content-type', res)) {
			return;
		}

		//#################################################################
		// Check, if the headers are valid
		//#################################################################

		// This header is provides by the keycloak proxy
		sub = options.headers['x-auth-subject'];

		appid = parseInt(options.headers['x-organicity-application'], 10);

		if(!Number.isInteger(appid)) {
			res.statusCode = 400;
			res.send('HTTP header x-organicity-application is not an integer!');
			return; 
		}

		expid = parseInt(options.headers['x-organicity-experiment'], 10);
		if(!Number.isInteger(appid)) {
			res.statusCode = 400;
			res.send('HTTP header x-organicity-experiment is not an integer!');
			return; 
		}

		if(options.headers['content-type'] !== 'application/json') {
			res.statusCode = 406;
			res.send('Content type ' + options.headers['content-type'] + ' not acceptable. Please provide application/json');
			return; 
		}

		console.log('### Data extracted from the header ###');
		console.log('appid:', appid);
		console.log('expid', expid);
		console.log('sub', sub);
		console.log('######################################');

		call1(req, res, options, body);
    };

    // Is experiment allowed to feed data
    var call1 = function(req, res, options, body) {
/*
      var optionsCall = {
          protocol: 'https',
          host: 'accounts.organicity.eu',
          port: '443',
          path: '/',
          method: 'GET'
      };

      httpClient.sendData(optionsCall, undefined, res, function(status, responseText, headers) {
        options.headers['X-organicity-call1'] = 'OKAY';
        call2(req, res, options, body);
      });
*/
      call2(req, res, options, body);
    };

    // This checks, if the sub is a participant/experimenter of the experiment
    var call2 = function(req, res, options, body) {

      // Check whether an experimenter is the owner of one experiment
      // GET /emscheck/experimentowner/{experId}/{expId}
      var optionsCall = {
          protocol: 'http',
          host: '31.200.243.76',
          port: '8081',
          path: '/emscheck/experimentowner/' + sub + '/' + expid,
          method: 'GET'
      };

      httpClient.sendData(optionsCall, undefined, res, function(status, responseText, headers) {
		// This will be called, if the sub is the expermenter of the experiment 
        call4(req, res, options, body);
      }, function() {
          // This will be called, if the sub is NOT the expermenter of the experiment
 
          // Check whether a participant takes part in the experiment
          // GET /emscheck/participant-experiment/{parId}/{expId}
		  var optionsCall = {
		      protocol: 'http',
		      host: '31.200.243.76',
		      port: '8081',
		      path: '/emscheck/participant-experiment/' + sub + '/' + expid,
		      method: 'GET'
		  };

		  httpClient.sendData(optionsCall, undefined, res, function(status, responseText, headers) {
			// This will be called, if the sub is a participant of the experiment
		    call4(req, res, options, body);
		  }, errorHandler(res));
      });





/*
      var optionsCall = {
          protocol: 'https',
          host: 'itm.uni-luebeck.de',
          port: '443',
          path: '/',
          method: 'GET'
      };

      httpClient.sendData(optionsCall, undefined, res, function(status, responseText, headers) {
        options.headers['X-organicity-call2'] = 'OKAY';
        call3(req, res, options, body);
      });
*/
      call3(req, res, options, body);
    };

    // Check whether an application belongs to one experiment
    var call3 = function(req, res, options, body) {
      var optionsCall = {
          protocol: 'http',
          host: '31.200.243.76',
          port: '8081',
          path: '/emscheck/application-experiment/' + expid + '/' + appid,
          method: 'GET'
      };

      httpClient.sendData(optionsCall, undefined, res, function(status, responseText, headers) {
        call4(req, res, options, body);
      }, errorHandler(res));
    };

    // Does the experiment have quota
    var call4 = function(req, res, options, body) {
/*      var optionsCall = {
          protocol: 'http',
          host: 'pro.server.organicity.eu',
          port: '80',
          path: '/',
          method: 'GET'
      };

      httpClient.sendData(optionsCall, undefined, res, function(status, responseText, headers) {
        options.headers['X-organicity-call4'] = 'OKAY';
        call5(req, res, options, body);
      });
*/
      call5(req, res, options, body);
    };

    // Check the validity of the asset
    var call5 = function(req, res, options, body) {

      // Handle body
      if(req.method === 'POST' && body) {
        var b = JSON.parse(body);
        console.log('Body:', b);
        if(b.username === 'xzy') {
          console.log('Everything is fine');
        } else {
          res.statusCode = 403;
          res.send('Username wrong');
          return;
        }
      }

      call6(req, res, options, body);
    };

    // Finally, Call the configured server
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

      call0(req, res, options, body);
    };

    return {
        pep: pep
    }
})();

exports.Root = Root;
