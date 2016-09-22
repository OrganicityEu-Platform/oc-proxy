var config = require('./../config.js');
var httpClient = require('./../lib/HTTPClient.js');
var log = require('./../lib/logger').logger.getLogger("Validation");

var validation = {};

var headerExists = function (headers, name, res, allowed) {
  console.log('Check for header: ', name, ' . ', allowed);

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

var errorHandler = function(res, code, msg) {
  return function(status, resp) {
      log.error('HTTP error. Status: ', status, 'Response: ', resp);
      res.statusCode = code || 500;
      res.send(msg || 'An internal server error happended!');
  }
}



validation.checkHeaderOrganicityApplication = function(req, res, options, body, done) {
  // This header must be privided by the client
  if(!headerExists(options.headers, 'x-organicity-application', res, true)) {
    return;
  }
  req.oc.appid = options.headers['x-organicity-application'];
  done();
}

validation.checkHeaderOrganicityExperiment = function(req, res, options, body, done) {
  // This header must be privided by the client
  if(!headerExists(options.headers, 'x-organicity-experiment', res, true)) {
    return;
  }
  req.oc.expid = options.headers['x-organicity-experiment'];
  done();
}

validation.checkHeaderAuthSub  = function(req, res, options, body, done) {
  // This header is provided by the keycloak proxy
  if(!headerExists(options.headers, 'x-auth-subject', res, true)) {
    return;
  }
  req.oc.sub = options.headers['x-auth-subject'];
  done();
}

validation.checkHeaderAccept  = function(req, res, options, body, done) {
  // The only valid accept header is JSON
  if(!headerExists(options.headers, 'accept', res, true)) {
    return;
  }

  if(options.headers['accept'] !== 'application/json') {
    res.statusCode = 406;
    res.send('Accept ' + options.headers['accept'] + ' not acceptable. Please provide application/json');
  }
  done();
}

validation.checkHeaderContentType  = function(req, res, options, body, done) {
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
  done();
}

validation.checkHeaderFiWare = function(req, res, options, body, done) {

  // This header must be privided by the client
  if(!headerExists(options.headers, 'fiware-service', res, false)) {
    return;
  }

  // This header must be privided by the client
  if(!headerExists(options.headers, 'fiware-servicepath', res, false)) {
    return;
  }

  done();
};

validation.printHeader  = function(req, res, options, body, done) {
  console.log('### Data extracted from the header');
  console.log('appid:       ', req.oc.appid);
  console.log('expid:       ', req.oc.expid);
  console.log('sub:         ', req.oc.sub);
  console.log('content-type:', options.headers['content-type']);
  console.log('accept:      ', options.headers['accept']);
  done();
}

validation.getAccessToken = function(req, res, options, body, done) {

  console.log('### Get access token');

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
    req.oc.access_token = token.access_token;
    done();
  });
};

// This checks, if the sub is a participant/experimenter of the experiment
validation.isSubParticipantExperimenterOfExperiment = function(req, res, options, body, done) {

  console.log('### Is sub a participant/experimenter of the experiment?');

  // Check whether an experimenter is the owner of one experiment
  // GET /emscheck/experimentowner/{experId}/{expId}
  var optionsCall = {
    protocol: config.experiment_management_api.protocol,
    host: config.experiment_management_api.host,
    port: config.experiment_management_api.port,
    path: '/emscheck/experimentowner/' + req.oc.sub + '/' + req.oc.expid,
    method: 'GET',
    headers : {
      'authorization' : 'Bearer: ' + req.oc.access_token
    }
  };

  httpClient.sendData(optionsCall, undefined, res, function(status, responseText, headers) {
    // This will be called, if the sub is the expermenter of the experiment
    done();
  }, function() {
    // This will be called, if the sub is NOT the expermenter of the experiment

    // Check whether a participant takes part in the experiment
    // GET /emscheck/participant-experiment/{parId}/{expId}
    var optionsCall = {
      protocol: config.experiment_management_api.protocol,
      host: config.experiment_management_api.host,
      port: config.experiment_management_api.port,
      path: '/emscheck/participant-experiment/' + req.oc.sub + '/' + req.oc.expid,
      method: 'GET',
      headers : {
        'authorization' : 'Bearer: ' + req.oc.access_token
      }
    };

    httpClient.sendData(optionsCall, undefined, res, function(status, responseText, headers) {
      // This will be called, if the sub is a participant of the experiment
      done();
    }, errorHandler(res, 400, 'You`re not part of the experiment'));
  });
};

// Check whether an application belongs to one experiment
validation.doesApplicationbelongToAnExperiment = function(req, res, options, body, done) {

  console.log('### Does an application belong to one experiment?');

  var optionsCall = {
    protocol: config.experiment_management_api.protocol,
    host: config.experiment_management_api.host,
    port: config.experiment_management_api.port,
    path: '/emscheck/application-experiment/' +  req.oc.expid + '/' +  req.oc.appid,
    method: 'GET',
    headers : {
      'authorization' : 'Bearer ' +  req.oc.access_token
    }
  };

  httpClient.sendData(optionsCall, undefined, res, function(status, responseText, headers) {
    done();
  }, errorHandler(res, 400, 'This application does not belong to the experiment'));
};

validation.isExperimentRunning = function(req, res, options, body, done) {
  console.log('### Is the experiment running?');

  var optionsCall = {
    protocol: config.experiment_management_api.protocol,
    host: config.experiment_management_api.host,
    port: config.experiment_management_api.port,
    path: '/emscheck/experimentrunning/' + req.oc.expid,
    method: 'GET',
    headers : {
      'authorization' : 'Bearer ' + req.oc.access_token
    }
  };

  httpClient.sendData(optionsCall, undefined, res, function(status, responseText, headers) {
    done();
  }, errorHandler(res, 400, 'This experiment is not running!'));
};

// Does the experiment have quota
validation.doesExperimentHaveQuota = function(req, res, options, body, done) {
  if(options.method === 'POST') {
    console.log('### Does the experiment have quota?');

    var optionsCall = {
      protocol: config.experiment_management_api.protocol,
      host: config.experiment_management_api.host,
      port: config.experiment_management_api.port,
      path: '/experiments/' + req.oc.expid + '/remainingquota',
      method: 'GET',
      headers : {
        'authorization' : 'Bearer ' + req.oc.access_token
      }
    };

    httpClient.sendData(optionsCall, undefined, res, function(status, responseText, headers) {
      var responseJson = JSON.parse(responseText);
      console.log('Quota: ', responseJson.remainingQuota);
      if(responseJson.remainingQuota > 0) {
        done();
      } else {
        res.statusCode = 400;
        res.send('The experiment reached the quota!');
      }
    }, errorHandler(res));
  } else {
    done();
  }
};


var validateAssetId = function(item_id, req, res, callback) {
  // Example
  // urn:oc:entity:experimenters:86d7edce-5092-44c0-bed8-da4beaa3fbc6:57d64f9cffd7cce42504bde3:4333
  // [0][1] [2]    [3]           [4]                                  [5]                      [6]
  //
  // [0]-[3] - handled by the prefix check
  //
  // [4] - main experimenter id
  // [5] - experiment id
  // [6] - assetid

  console.log('### Check the validity of the assetId');

  console.log('id: ', item_id);

  if(!item_id.startsWith('urn:oc:entity:experimenters')) {
    res.statusCode = 400;
    res.send('asset.id prefix wrong');
    return;
  }

  var urn_parts = item_id.split(':');
  var urn_main_experimenter_id = urn_parts[4];
  var urn_experiment_id = urn_parts[5];
  var urn_asset_id = urn_parts[6];

  console.log('Prefix:', 'urn:oc:entity:experimenters');
  console.log('urn_main_experimenter_id:', urn_main_experimenter_id);
  console.log('urn_experiment_id:', urn_experiment_id);
  console.log('urn_asset_id:', urn_asset_id);

  // (b) Check for the correct experiment id
  if(urn_experiment_id !== req.oc.expid){
      res.statusCode = 400;
      res.send('The given experiment id `' + urn_experiment_id + '` within th asset id is wrong');
      return;
  }

  // (c) Check, if the main experimenter id within the URN of the asset equals the main experimenter id
  var optionsCall = {
    protocol: config.experiment_management_api.protocol,
    host: config.experiment_management_api.host,
    port: config.experiment_management_api.port,
    path: '/experiments/' + req.oc.expid + '/mainexperimenter',
    method: 'GET',
    headers : {
      'authorization' : 'Bearer ' + req.oc.access_token
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

validation.checkValidityOfAssetId = function(req, res, options, body, done) {

  if(req.method === 'PUT' || req.method === 'DELETE') {
    console.log('### Check the validity of the asset ID ###');

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
    validateAssetId(assetId, req, res, done);
  } else {
    done();
  }
};

validation.checkValidityOfAsset = function(req, res, options, body, done) {

  if(req.method === 'POST') {
    console.log('### Check the validity of the body');

    // Handle body

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

    console.log(asset.id);
    validateAssetId(asset.id, req, res, function() {
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
            'authorization' : 'Bearer ' + req.oc.access_token
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
          done();
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
              'authorization' : 'Bearer ' + req.oc.access_token,
              'content-type' : 'application/json'
            }
          };

          var newAsset = {
            name: assetName
          };

          httpClient.sendData(optionsCall, JSON.stringify(newAsset), res, function(status, responseText, headers) {
            // Push unregisteredassettype was successful
            done();
          });
        }
      }, errorHandler(res));
    }); // validateAssetId
  }
};

validation.addFiWareSignature = function(req, res, options, body, done) {
  console.log('### Add FIWARE signature.');
  options.headers['Fiware-Service'] = 'organicity';
  options.headers['Fiware-ServicePath'] = '/';
  done();
};

validation.sendResponse = function(req, res, options, body, done) {
    res.send(res.responseText);
};

validation.decreaseQuota = function(req, res, options, body, done) {

  if(options.method === 'POST') {
    console.log('### Decrease the Quota');

    var optionsCall = {
      protocol: config.experiment_management_api.protocol,
      host: config.experiment_management_api.host,
      port: config.experiment_management_api.port,
      path: '/experiments/' + req.oc.expid + '/decreaseremquota',
      method: 'POST',
      headers : {
        'authorization' : 'Bearer ' + req.oc.access_token
      }
    };

    httpClient.sendData(optionsCall, undefined, res, done, errorHandler(res));
    return;
  }
  done();
}

validation.increaseQuota = function(req, res, options, body, done) {
  if(options.method === 'DELETE') {
    console.log('### Increase the Quota');

    var optionsCall = {
      protocol: config.experiment_management_api.protocol,
      host: config.experiment_management_api.host,
      port: config.experiment_management_api.port,
      path: '/experiments/' + req.oc.expid + '/increaseremquota',
      method: 'POST',
      headers : {
        'authorization' : 'Bearer ' + req.oc.access_token
      }
    };

    httpClient.sendData(optionsCall, undefined, res, done, errorHandler(res));
    return;
  }
  done();
};

// Finally, Call the configured server
validation.callFinalServer = function(req, res, options, body, done){

  console.log('### Forward message to the configured server.');

  // Add x-forwarded-for header
  options.headers = httpClient.getClientIp(req, req.headers);

  httpClient.sendData(options, body, res,
  function(status, responseText, headers) {
    // Prepare the response
    res.statusCode = status;
    for (var idx in headers) {
        var header = headers[idx];
        res.setHeader(idx, headers[idx]);
    }
    res.responseText = responseText;
    done();
  });
};


module.exports = validation;
