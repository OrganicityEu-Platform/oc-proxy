var config = require('./../config.js'),
    httpClient = require('./../lib/HTTPClient.js');

require('string.prototype.startswith');

var log = require('./../lib/logger').logger.getLogger("Root");

var Root = (function() {

	var appid = 0;
	var expid = 0;
	var sub = undefined;
	var access_token = undefined;

	var headerExists = function (headers, name, res) {
    console.log('   Check for header: ' + name);
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
		    res.statusCode = 500;
		    res.send('An internal server error happended!');
		}
	}

  // Check HTTP headers
  var call0 = function(req, res, options, body) {

		console.log('0) Check HTTP headers?');

		//#################################################################
		// Check, if some headers do exist
		//#################################################################

    // This header must be privided by the client
		if(!headerExists(options.headers, 'x-organicity-application', res)) {
			return;
		}
    appid = options.headers['x-organicity-application'];

    // This header must be privided by the client
		if(!headerExists(options.headers, 'x-organicity-experiment', res)) {
			return;
		}
    expid = options.headers['x-organicity-experiment'];

		// This header is provided by the keycloak proxy
		if(!headerExists(options.headers, 'x-auth-subject', res)) {
			return;
		}
		sub = options.headers['x-auth-subject'];

    // The only valid accept header is JSON
		if(!headerExists(options.headers, 'accept', res)) {
			return;
		}
		if(options.headers['accept'] !== 'application/json') {
			res.statusCode = 406;
			res.send('Accept ' + options.headers['accept'] + ' not acceptable. Please provide application/json');
			return;
		}

    if(options.method === 'POST') {
      // The only valid content-type header is JSON
      if(!headerExists(options.headers, 'content-type', res)) {
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

    call1(req, res, options, body);
  };


    var call1 = function(req, res, options, body) {

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
        call1_1(req, res, options, body);
      });
		};

    // Is experiment allowed to feed data
    var call1_1 = function(req, res, options, body) {

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
        call2(req, res, options, body);
      });
*/

      call2(req, res, options, body);
    };

    // This checks, if the sub is a participant/experimenter of the experiment
    var call2 = function(req, res, options, body) {

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
        call3(req, res, options, body);
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
          call3(req, res, options, body);
        }, errorHandler(res));
      });
    };

    // Check whether an application belongs to one experiment
    var call3 = function(req, res, options, body) {

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
        call4(req, res, options, body);
      }, errorHandler(res));
    };

    // Does the experiment have quota
    var call4 = function(req, res, options, body) {

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
          call5(req, res, options, body);
        } else {
          res.statusCode = 400;
          res.send('The experiment reached the quota!');
          return;
        }
      }, errorHandler(res));

    };

    // Check the validity of the asset
    var call5 = function(req, res, options, body) {

			console.log('6) Check the validity of the asset');

      // Handle body
      if(req.method === 'POST') {

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

				if(asset.id != undefined){

					// Example
					// urn:oc:entity:experimenters:86d7edce-5092-44c0-bed8-da4beaa3fbc6:57d64f9cffd7cce42504bde3:4333
					// [0][1] [2]    [3]           [4]                                  [5]                      [6]
					//
					// [0]-[3] -handles by prefix check
					//
					// [4] - main experimenter id
					// [5] - experiment id
					// [6] - assetid

					var item_id = asset.id;
					var item_type = asset.type;
					var item_servicePath = asset.servicePath;

					// (a) Validate the asset id
					if(item_id != undefined){
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

              if(urn_main_experimenter_id !== mainExperimenter) {
                res.statusCode = 400;
								res.send('The given experimenter id `' + urn_main_experimenter_id + '` within th asset id is wrong');
                return;
              }

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
                  call6(req, res, options, body);
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
                    call6(req, res, options, body);
                  });
								}

							}, errorHandler(res));

						}, errorHandler(res));

					} else {
						res.statusCode = 400;
						res.send('asset.id wrong');
						return;
					}

				} else {
					res.statusCode = 403;
					res.send('asset.id not provided!');
					return;
				}

			} else {

        // GET, DELETE, ...
        call6(req, res, options, body);
      }

    };

    // Finally, Call the configured server
    var call6 = function(req, res, options, body){

			console.log('7) Add FIWARE signature.');

			options.headers['Fiware-Service'] = 'organicity';
			options.headers['Fiware-ServicePath'] = '/';

			console.log('8) Forward message to the configured server.');

      // Add x-forwarded-for header
      options.headers = httpClient.getClientIp(req, req.headers);

      console.log(options);

      httpClient.sendData(options, body, res,
      function(status, responseText, headers) {
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

          httpClient.sendData(optionsCall, undefined, res, callBackOK, errorHandler(res));
        //} else if (options.method === 'DELETE') {
        //
        //console.log('9) Increase the Quota');
        } else {
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
