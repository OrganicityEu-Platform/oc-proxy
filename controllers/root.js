var config = require('./../config.js'),
    httpClient = require('./../lib/HTTPClient.js'),
    url = require('url');
require('string.prototype.startswith');

var log = require('./../lib/logger').logger.getLogger("Root");

var Root = (function() {

	var appid = 0;
	var expid = 0;
	var sub = undefined;
	var access_token = undefined;

	var headerExists = function (headers, name, res, allowed) {
    console.log('   Check for header: ', name, ' . ', allowed);

    // Header is mandatory
    if(allowed) {
		  if(!headers[name]) {
        res.statusCode = 400;
        res.send('HTTP header ' + name.toLowerCase() + ' not provided!');
        return false;
      }
      return true;
    }

    // Header is not allowed
    else {
		  if(headers[name]) {
        res.statusCode = 400;
        res.send('HTTP header ' + name.toLowerCase() + ' is not allowed!');
        return false;
      }
      return true;
    }
	}

	var errorHandler = function(res) {
		return function(status, resp) {
		    log.error('HTTP error. Status: ', status, 'Response: ', resp);
		    res.statusCode = 500;
		    res.send('An internal server error happended!');
		}
	}

  // Check HTTP headers
  var call0 = function(req, res, options, body) {

		console.log('0) Check HTTP headers?');
    //console.log(options.headers);

		//#################################################################
		// Check, if some invalid headers do exist
		//#################################################################

    // This header must be privided by the client
		if(!headerExists(options.headers, 'fiware-service', res, false)) {
			return;
		}

		if(!headerExists(options.headers, 'fiware-servicepath', res, false)) {
			return;
		}

		//#################################################################
		// Check, if some headers do exist
		//#################################################################

    // This header must be privided by the client
		if(!headerExists(options.headers, 'x-organicity-application', res, true)) {
			return;
		}
    appid = options.headers['x-organicity-application'];

    // This header must be privided by the client
		if(!headerExists(options.headers, 'x-organicity-experiment', res, true)) {
			return;
		}
    expid = options.headers['x-organicity-experiment'];

		// This header is provided by the keycloak proxy
		if(!headerExists(options.headers, 'x-auth-subject', res, true)) {
			return;
		}
		sub = options.headers['x-auth-subject'];

    // The only valid accept header is JSON
		if(!headerExists(options.headers, 'accept', res, true)) {
			return;
		}

		if(options.headers['accept'] !== 'application/json') {
			res.statusCode = 406;
			res.send('Accept ' + options.headers['accept'] + ' not acceptable. Please provide application/json');
			return;
		}

    if(options.method === 'POST' || options.method === 'PUT') {
      // The only valid content-type header is JSON
      if(!headerExists(options.headers, 'content-type', res, true)) {
        return;
      }
      if(options.headers['content-type'] !== 'application/json') {
        res.statusCode = 406;
        res.send('Content type ' + options.headers['content-type'] + ' not acceptable. Please provide application/json');
        return;
      }
    }

		console.log('   ##### Data extracted from the header #####');
		console.log('   appid:       ', appid);
		console.log('   expid:       ', expid);
		console.log('   sub:         ', sub);
		console.log('   content-type:', options.headers['content-type']);
		console.log('   ##########################################');

    getAccessToken(req, res, options, body);
  };


    var getAccessToken = function(req, res, options, body) {

			console.log('1) Get access token');

      var optionsCall = {
          protocol: config.accounts_token_endpoint.protocol,
          host: config.accounts_token_endpoint.host,
          port: config.accounts_token_endpoint.port,
          path: config.accounts_token_endpoint.path,
          method: 'POST',
					headers: {
						'Content-Type' : 'application/x-www-form-urlencoded'
					}
      };

			var body2 = 'grant_type=client_credentials&client_id=' + config.client_id + '&client_secret=' + config.client_secret;

      httpClient.sendData(optionsCall, body2, res, function(status, responseText, headers) {
				var token = JSON.parse(responseText);
				access_token = token.access_token;
        isExperiementAllowedToFeedData(req, res, options, body);
      });
		};

    // Is experiment allowed to feed data
    var isExperiementAllowedToFeedData = function(req, res, options, body) {

			console.log('2) Is experiment allowed to feed data?');
			console.log('   TODO');

			// TODO: Call `Is experiment allowed to feed data`

/*
      var optionsCall = {
          protocol: '',
          host: '',
          port: '',
          path: '',
          method: ''
      };

      httpClient.sendData(optionsCall, undefined, res, function(status, responseText, headers) {
        options.headers['X-organicity-call1'] = 'OKAY';
        isSubParticipantExperimenterOfExperiment(req, res, options, body);
      });
*/

      isSubParticipantExperimenterOfExperiment(req, res, options, body);
    };

    // This checks, if the sub is a participant/experimenter of the experiment
    var isSubParticipantExperimenterOfExperiment = function(req, res, options, body) {

			console.log('3) Is sub a participant/experimenter of the experiment?');

      // Check whether an experimenter is the owner of one experiment
      // GET /emscheck/experimentowner/{experId}/{expId}
      var optionsCall = {
          protocol: config.experiment_management_api.protocol,
          host: config.experiment_management_api.host,
          port: config.experiment_management_api.port,
          path: '/emscheck/experimentowner/' + sub + '/' + expid,
          method: 'GET',
					headers : {
						'authorization' : 'Bearer: ' + access_token
					}
      };

      httpClient.sendData(optionsCall, undefined, res, function(status, responseText, headers) {
		// This will be called, if the sub is the expermenter of the experiment
        doesApplicationbelongToAnExperiment(req, res, options, body);
      }, function() {
				// This will be called, if the sub is NOT the expermenter of the experiment

				// Check whether a participant takes part in the experiment
        // GET /emscheck/participant-experiment/{parId}/{expId}
        var optionsCall = {
            protocol: config.experiment_management_api.protocol,
            host: config.experiment_management_api.host,
            port: config.experiment_management_api.port,
            path: '/emscheck/participant-experiment/' + sub + '/' + expid,
            method: 'GET',
						headers : {
							'authorization' : 'Bearer: ' + access_token
						}
        };

        httpClient.sendData(optionsCall, undefined, res, function(status, responseText, headers) {
        // This will be called, if the sub is a participant of the experiment
          doesApplicationbelongToAnExperiment(req, res, options, body);
        }, errorHandler(res));
      });
    };

    // Check whether an application belongs to one experiment
    var doesApplicationbelongToAnExperiment = function(req, res, options, body) {

			console.log('4) Does an application belong to one experiment?');

      var optionsCall = {
          protocol: config.experiment_management_api.protocol,
          host: config.experiment_management_api.host,
          port: config.experiment_management_api.port,
          path: '/emscheck/application-experiment/' + expid + '/' + appid,
          method: 'GET',
					headers : {
						'authorization' : 'Bearer ' + access_token
					}
      };

      httpClient.sendData(optionsCall, undefined, res, function(status, responseText, headers) {
        isExperimentRunning(req, res, options, body);
      }, errorHandler(res));

    };

    var isExperimentRunning = function(req, res, options, body) {
			console.log('4) is the experiment running?');

      var optionsCall = {
        protocol: config.experiment_management_api.protocol,
        host: config.experiment_management_api.host,
        port: config.experiment_management_api.port,
        path: '/emscheck/experimentrunning/' + expid,
        method: 'GET',
        headers : {
          'authorization' : 'Bearer ' + access_token
        }
      };

      var errorHandlerExperimentRunning = function(res) {
        return function(status, resp) {
          log.error('HTTP error. Status: ', status, 'Response: ', resp);
          res.statusCode = 400;
          res.send('The experiment is not running!');
        }
      }

      httpClient.sendData(optionsCall, undefined, res, function(status, responseText, headers) {
        console.log('It runs!');
        doesExperimentHaveQuota(req, res, options, body);
      }, errorHandlerExperimentRunning(res));
    }

    // Does the experiment have quota
    var doesExperimentHaveQuota = function(req, res, options, body) {

      if(options.method === 'POST') {
        console.log('5) Does the experiment have quota?');

        var optionsCall = {
            protocol: config.experiment_management_api.protocol,
            host: config.experiment_management_api.host,
            port: config.experiment_management_api.port,
            path: '/experiments/' + expid + '/remainingquota',
            method: 'GET',
            headers : {
              'authorization' : 'Bearer ' + access_token
            }
        };

        httpClient.sendData(optionsCall, undefined, res, function(status, responseText, headers) {
          var responseJson = JSON.parse(responseText);
          console.log('   Quota: ', responseJson.remainingQuota);
          if(responseJson.remainingQuota > 0) {
            checkValidityOfAsset(req, res, options, body);
          } else {
            res.statusCode = 400;
            res.send('The experiment reached the quota!');
            return;
          }
        }, errorHandler(res));
      } else {
        checkValidityOfAsset(req, res, options, body);
      }
    };

    var validateBody = function(req, res, options, body) {

      console.log('6b) Check the validity of the body');

      if(!body) {
        res.statusCode = 400;
        res.send('No body provided!');
        return;
      }

      var asset;
      try {
        asset = JSON.parse(body);
      } catch (e) {
        res.statusCode = 400;
        res.send('Body is not valid JSON!');
        return;
      }

      if(asset.id === undefined){
        res.statusCode = 403;
        res.send('asset.id not provided!');
        return;
      }

      validateAssetId(asset.id, res, function() {
        var item_type = asset.type;

        // (d) Check, if non allowed attributes are used
        for (var i = 0; i < config.bad_asset_attributes.length; i++) {
          var a = config.bad_asset_attributes[i];
          if(asset[a]) {
            res.statusCode = 400;
            res.send('Attribute ' + bad_attribues[i] + ' not allowed!');
            return;
          }
        }

        var allowedPrefix = 'urn:oc:entitytype:';

        // (e) Check, if the prefix of the asset is correct
        if(!item_type.startsWith(allowedPrefix)) {
          res.statusCode = 400;
          res.send('asset.type prefix wrong');
          return;
        }

        // (f) Get the available assetTypes from the OrganiCity Platform Management API
        var optionsCall = {
            protocol: config.platform_management_api.protocol,
            host: config.platform_management_api.host,
            port: config.platform_management_api.port,
            path: '/v1/dictionary/assettypes',
            method: 'GET',
            headers : {
              'authorization' : 'Bearer ' + access_token
            }
        };

        httpClient.sendData(optionsCall, undefined, res, function(status, responseText, headers) {
          var assetTypes = JSON.parse(responseText);

          var found = false;
          for (var i = 0; i < assetTypes.length; i++) {
            var a = assetTypes[i];
            if(item_type === a.urn) {
              console.log('   ', a.urn);
              found = true;
            }
          }

          if(found) {
            console.log('   Asset type found!');
            callFinalServer(req, res, options, body);
          } else {

            // If the assed cannot be found, we inform the `OrganiCity Platform Management API` about it

            // Remove the prefix before posting
            var assetName = item_type.substring(allowedPrefix.length);

            console.log('   Asset unknown. Inform `OrganiCity Platform Management API` about the new asset type: `', assetName, '`');

            var optionsCall = {
                protocol: config.platform_management_api.protocol,
                host: config.platform_management_api.host,
                port: config.platform_management_api.port,
                path: '/v1/dictionary/unregisteredassettype',
                method: 'POST',
                headers : {
                  'authorization' : 'Bearer ' + access_token,
                  'content-type' : 'application/json'
                }
            };

            var newAsset = {
              name: assetName
            };

            httpClient.sendData(optionsCall, JSON.stringify(newAsset), res, function(status, responseText, headers) {
              // Push unregisteredassettype was successful
              callFinalServer(req, res, options, body);
            });
          }
        }, errorHandler(res));
      }); // validateAssetId

    };

    var validateAssetId = function(item_id, res, callback) {
      // Example
      // urn:oc:entity:experimenters:86d7edce-5092-44c0-bed8-da4beaa3fbc6:57d64f9cffd7cce42504bde3:4333
      // [0][1] [2]    [3]           [4]                                  [5]                      [6]
      //
      // [0]-[3] - handled by the prefix check
      //
      // [4] - main experimenter id
      // [5] - experiment id
      // [6] - assetid

      console.log('6) Check the validity of the assetId');

      console.log('   id: ', item_id);

      if(!item_id.startsWith('urn:oc:entity:experimenters')) {
        res.statusCode = 400;
        res.send('asset.id prefix wrong');
        return;
      }

      var urn_parts = item_id.split(':');
      var urn_main_experimenter_id = urn_parts[4];
      var urn_experiment_id = urn_parts[5];
      var urn_asset_id = urn_parts[6];

      console.log('   Prefix:', 'urn:oc:entity:experimenters');
      console.log('   urn_main_experimenter_id:', urn_main_experimenter_id);
      console.log('   urn_experiment_id:', urn_experiment_id);
      console.log('   urn_asset_id:', urn_asset_id);

      // (b) Check for the correct experiment id
      if(urn_experiment_id !== expid){
          res.statusCode = 400;
          res.send('The given experiment id `' + urn_experiment_id + '` within th asset id is wrong');
          return;
      }

      // (c) Check, if the main experimenter id within the URN of the asset equals the main experimenter id
      var optionsCall = {
        protocol: config.experiment_management_api.protocol,
        host: config.experiment_management_api.host,
        port: config.experiment_management_api.port,
        path: '/experiments/' + expid + '/mainexperimenter',
        method: 'GET',
        headers : {
          'authorization' : 'Bearer ' + access_token
        }
      };
      httpClient.sendData(optionsCall, undefined, res, function(status, responseText, headers) {

        var responseJson = JSON.parse(responseText);
        var mainExperimenter = responseJson.mainExperimenter;

        console.log(urn_main_experimenter_id);
        console.log(mainExperimenter);

        if(urn_main_experimenter_id !== mainExperimenter) {
          res.statusCode = 400;
          res.send('The given experimenter id `' + urn_main_experimenter_id + '` within th asset id is wrong');
          return;
        }
        callback();
      }, errorHandler(res));

    }


    // Check the validity of the asset
    var checkValidityOfAsset = function(req, res, options, body) {

      console.log('### Check the validity of the asset ###');

      if(req.method === 'PUT' || req.method === 'DELETE') {

        var pathname = url.parse(req.url, true).pathname;
        console.log('pathname:', pathname);

        if(!pathname.startsWith('/v2/entities/urn:oc:entity:experimenters:')) {
          res.statusCode = 400;
          res.send('Path must be like /v2/entities/urn:oc:entity:experimenters:...');
          return;
        }

        var pathname_parts = pathname.split('/');
        if(pathname_parts.length != 4) {
          console.log(pathname_parts.length);
          res.statusCode = 400;
          res.send('Path to long or to short!');
          return;
        }

        var assetId = pathname_parts[3];
        console.log('Validate asset.id: ', pathname_parts[3]);
        validateAssetId(assetId, res, function() {
          if(req.method === 'PUT') {
            validateBody(req, res, options, body);
          } else if(req.method === 'DELETE') {
            callFinalServer(req, res, options, body);
          }
        });
        return;
      } else if(req.method === 'POST') {
        // Handle body
        validateBody(req, res, options, body);
      } else {
        // GET
        callFinalServer(req, res, options, body);
      }
    };

    // Finally, Call the configured server
    var callFinalServer = function(req, res, options, body){

			console.log('7) Add FIWARE signature.');

			options.headers['Fiware-Service'] = 'organicity';
			options.headers['Fiware-ServicePath'] = '/';

			console.log('8) Forward message to the configured server.');

      // Add x-forwarded-for header
      options.headers = httpClient.getClientIp(req, req.headers);

      httpClient.sendData(options, body, res,
      function(status, responseText, headers) {

        var callBackOK = function() {
            // Return the inital status code from the asset creation
            res.statusCode = status;
            for (var idx in headers) {
                var header = headers[idx];
                res.setHeader(idx, headers[idx]);
            }
            log.debug("Response: ", status);
            log.debug(" Body: ", responseText);
            res.send(responseText);
        };

        if(options.method === 'POST') {
          console.log('9) Decrease the Quota');

          var optionsCall = {
              protocol: config.experiment_management_api.protocol,
              host: config.experiment_management_api.host,
              port: config.experiment_management_api.port,
              path: '/experiments/' + expid + '/decreaseremquota',
              method: 'POST',
              headers : {
                'authorization' : 'Bearer ' + access_token
              }
          };

          httpClient.sendData(optionsCall, undefined, res, callBackOK, errorHandler(res));
        } else if(options.method === 'DELETE') {
          console.log('9) Increase the Quota');

          var optionsCall = {
              protocol: config.experiment_management_api.protocol,
              host: config.experiment_management_api.host,
              port: config.experiment_management_api.port,
              path: '/experiments/' + expid + '/increaseremquota',
              method: 'POST',
              headers : {
                'authorization' : 'Bearer ' + access_token
              }
          };

          httpClient.sendData(optionsCall, undefined, res, callBackOK, errorHandler(res));
        } else {
          for (var idx in headers) {
              var header = headers[idx];
              res.setHeader(idx, headers[idx]);
          }
          res.statusCode = status;
          res.send(responseText);
        }

      });

    }

    var pep = function(req, res) {

      var options = {
          protocol: config.application_endpoint.protocol,
          host: config.application_endpoint.host,
          port: config.application_endpoint.port,
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
