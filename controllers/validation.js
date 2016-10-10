var config = require('./../config.js');
var httpClient = require('./../lib/HTTPClient.js');
var log = require('./../lib/logger').logger.getLogger("Validation");
var url = require('url');
var indexOf = require('indexof-shim');

var redis = require("redis").createClient();
var lock = require("redis-lock")(redis);

var jwt = require('jsonwebtoken');
var fs = require('fs');
var cert = fs.readFileSync('cert.pem');

require('string.prototype.startswith');

var validation = {};

var headerExists = function (headers, name, res, allowed) {
  console.log('### Check for header: ', name, ' ', allowed);

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
};

var errorHandler = function(res, code, msg) {
  return function(status, resp) {
      log.error('HTTP error. Status: ', status, 'Response: ', resp);
      res.statusCode = code || 500;
      res.send(msg || 'An internal server error happended!');
  }
};

validation.init = function(req, res, next) {
  req.oc = {};
  next();
};

validation.rolehandler = function (roles) {
	return function(req, res, next) {
		for(var i = 0; i < roles.length; i++) {
			var role = roles[i];
			console.log('\n### Check role: ', role);
			if(indexOf(req.user.token.realm_access.roles, role) >= 0) {
				req.headers['x-auth-subject'] = req.user.token.sub;
        console.log('found');
				next();
				return;
			}
		}
    console.log('not found');
		res.status(403).send('You dont have to role to access this endpoint!');
	}
};

validation.checkHeaderOrganicityApplication = function(req, res, next) {
  // This header must be privided by the client
  if(!headerExists(req.headers, 'x-organicity-application', res, true)) {
    return;
  }
  req.oc.appid = req.headers['x-organicity-application'];
  next();
};

validation.checkHeaderOrganicityExperiment = function(req, res, next) {
  // This header must be privided by the client
  if(!headerExists(req.headers, 'x-organicity-experiment', res, true)) {
    return;
  }
  req.oc.expid = req.headers['x-organicity-experiment'];
  next();
};

validation.checkHeaderAuthSub  = function(req, res, next) {
  // This header is provided by the keycloak proxy
  if(!headerExists(req.headers, 'x-auth-subject', res, true)) {
    return;
  }
  req.oc.sub = req.headers['x-auth-subject'];
  next();
};

validation.checkHeaderAccept  = function(req, res, next) {
  // The only valid accept header is JSON
  if(!headerExists(req.headers, 'accept', res, true)) {
    return;
  }

  if(req.headers['accept'] !== 'application/json') {
    res.statusCode = 406;
    res.send('HTTP header Accept ' + req.headers['accept'] + ' not acceptable. Please provide application/json');
  }
  next();
};

validation.checkHeaderContentType  = function(req, res, next) {
  // The only valid content-type header is JSON
  if(!headerExists(req.headers, 'content-type', res, true)) {
    return;
  }
  if(req.headers['content-type'] !== 'application/json') {
    res.statusCode = 406;
    res.send('HTTP header Content-Type ' + req.headers['content-type'] + ' not acceptable. Please provide application/json');
    return;
  }
  next();
};

validation.checkHeaderFiware  = function(req, res, next) {

  // This header must be privided by the client
  if(!headerExists(req.headers, 'fiware-service', res, true)) {
    return;
  }

  if(req.headers['fiware-service'] !== 'organicity') {
    res.statusCode = 406;
    res.send('HTTP header Fiware-Service ' + req.headers['fiware-service'] + ' not acceptable.');
    return;
  }

  next();
};

validation.checkHeaderFiwareAbstinence = function(req, res, next) {

  // This header must be privided by the client
  if(!headerExists(req.headers, 'fiware-service', res, false)) {
    return;
  }

  // This header must be privided by the client
  if(!headerExists(req.headers, 'fiware-servicepath', res, false)) {
    return;
  }

  next();
};


validation.printHeader  = function(req, res, next) {
  console.log('\n### Data extracted from the header');
  console.log('appid:       ', req.oc.appid);
  console.log('expid:       ', req.oc.expid);
  console.log('sub:         ', req.oc.sub);
  console.log('content-type:', req.headers['content-type']);
  console.log('accept:      ', req.headers['accept']);
  next();
}

validation.getAccessToken = function(req, res, next) {

  console.log('\n### Get access token');

  console.log('Get access token from cache');
  lock("oc.accessToken", function(unlock) {
    console.log('We got the lock!');
    var done = function() {
      console.log('Unlock');
      unlock(); // unlock
      next(); // next step in chain
    }

    redis.get("oc.accessToken", function (err, reply) {
      if(err || !reply) {
        console.log('No access token in cache. Renew token!');

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

        var payload = 'grant_type=client_credentials&client_id=' + config.client_id + '&client_secret=' + config.client_secret;

        httpClient.sendData(optionsCall, payload, res, function(status, responseText, headers) {
          var token = JSON.parse(responseText);
          req.oc.access_token = token.access_token;
          console.log(req.oc.access_token);
          redis.setex("oc.accessToken", ((4*60) + 30), token.access_token, done);
        },function(status, resp) {
          done();
          log.error("Error: ", status, resp);
          res.statusCode = status;
          res.send(resp);
        });

      } else {
        var decoded = jwt.verify(reply.toString(), cert);
        var now = Math.floor(Date.now() / 1000);
        var sec = decoded.exp - now;
        console.log('Use access token from the cache. Expires in ', sec, 's');

        req.oc.access_token = reply.toString();
        console.log(req.oc.access_token);
        done();
      }
    }); // get
	}); // lock
};

// This checks, if the sub is a participant/experimenter of the experiment
validation.isSubParticipantExperimenterOfExperiment = function(req, res, next) {
  console.log('\n### Is sub a participant/experimenter of the experiment?');

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
    next();
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
      next();
    }, errorHandler(res, 400, 'You`re not part of the experiment'));
  });
};

// Check whether an application belongs to one experiment
validation.doesApplicationbelongToAnExperiment = function(req, res, next) {

  console.log('\n### Does an application belong to one experiment?');

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
    next();
  }, errorHandler(res, 400, 'This application does not belong to the experiment'));
};

validation.isExperimentRunning = function(req, res, next) {
  console.log('\n### Is the experiment running?');

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
    next();
  }, errorHandler(res, 400, 'This experiment is not running!'));
};

// Does the experiment have quota
validation.doesExperimentHaveQuota = function(req, res, next) {
  console.log('\n### Does the experiment have quota?');

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
    var quota = responseJson.remainingQuota;

    console.log('Quota: ', quota);
    if(quota > 0) {
      next();
    } else {
      res.statusCode = 400;
      res.send('The experiment reached the quota!');
    }
  }, errorHandler(res));
};

// req.oc.sitename must be known prior from the token!
validateSiteAssetId = function(assetId, req, res, next) {

  console.log('\n### Check the validity of the assetId (site)');

  // ID within the user token: ocsite-<SITENAME>
  // ID within the asset:      urn:oc:entity:<SITENAME>
  var allowedPrefix = 'urn:oc:entity:' + req.oc.sitename + ':';

  console.log(assetId);
  console.log(allowedPrefix);

  // Check, if the prefix of the asset is correct
  if(!assetId.startsWith(allowedPrefix)) {
    res.statusCode = 400;
    res.send('asset.id prefix wrong');
    return;
  }

  req.oc.assetId = assetId;
  next();
};

var validateExperimenterAssetId = function(assetId, req, res, next) {
  // Example
  // urn:oc:entity:experimenters:86d7edce-5092-44c0-bed8-da4beaa3fbc6:57d64f9cffd7cce42504bde3:4333
  // [0][1] [2]    [3]           [4]                                  [5]                      [6]
  //
  // [0]-[3] - handled by the prefix check
  //
  // [4] - main experimenter id
  // [5] - experiment id
  // [6] - assetid

  console.log('\n### Check the validity of the asset ID (experimenters)');

  console.log('id: ', assetId);

  if(!assetId.startsWith('urn:oc:entity:experimenters:')) {
    res.statusCode = 400;
    res.send('asset.id prefix wrong');
    return;
  }

  var urn_parts = assetId.split(':');
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
    console.log('AssetID valid!');
    next();
  }, errorHandler(res));

}

validation.checkValidityOfExperimenterAssetIdFromParam = function(req, res, next) {
  validateExperimenterAssetId(req.params.assetId, req, res, next);
};

validation.checkValidityOfSiteAssetIdFromParam = function(req, res, next) {
  validateSiteAssetId(req.params.assetId, req, res, next);
};

// This handler gets gets the body as JSON and adds it
// add it as req.oc.asset
validation.getAssetFromBody = function(req, res, next) {

  console.log('\n### Get the Asset from the body');

  // Handle body
  if(!req.body) {
    res.statusCode = 400;
    res.send('No body provided!');
    return;
  }

  try {
    req.oc.asset = JSON.parse(req.body.toString('utf8'));
  } catch (e) {
    res.statusCode = 400;
    res.send('Body is not valid JSON!');
    return;
  }

  console.log('done');
  next();

};

validation.checkSiteToken = function(req, res, next) {
  console.log('\n### Check site token');
  // OC sites are Clients, thus, we grab the client id from the Access Token

  var clientId = req.user.token.clientId;
  if(!clientId) {
    res.statusCode = 400;
    res.send('You are not a client!');
    return;
  }

  var clientIdParts = clientId.split('-');

  if(clientIdParts.length != 2) {
    res.statusCode = 400;
    res.send('ClientID wrong');
    return;
  }

  if(clientIdParts[0] != 'ocsite') {
    res.statusCode = 400;
    res.send('ClientID wrong. You`re not an OC site.');
    return;
  }

  // ID within the user token: ocsite-<SITENAME>
  var sitename = clientIdParts[1];
  req.oc.sitename = sitename;
  next();
};

// This handler checks, if the id from the token (e.g., site) and the
// assetid within the Asset are the same
// If valid, req.oc.sitename will contain the sitename
validation.checkValidityOfSiteAssetIdFromBody = function(req, res, next) {
  var asset = req.oc.asset;
  // The AssetID is an attribute `id` within the asset
  validateSiteAssetId(asset.id, req, res, function() {
    // Site is authorized to push assets with that prefix
    next();
  });
};

validation.checkValidityOfExperimenterAssetIdFromBody = function(req, res, next) {
  var asset = req.oc.asset;
  validateExperimenterAssetId(asset.id, req, res, function() {
    next();
  });
};

validation.checkForNonAllowedAttribute = function(attr) {
  return function(req, res, next) {
    console.log('\n### Check, if asset.' + attr + ' does not exists');
    var asset = req.oc.asset;

    if(asset[attr]) {
      console.log('Asset attribute ' + attr + ' in payload not allowed!');
      res.statusCode = 400;
      res.send('Asset attribute ' + attr + ' in payload not allowed!');
      return;
    } else {
      console.log('Asset attribute ' + attr + ' not included!');
      next();
    }
  };
};

validation.checkForNonAllowedAttributes = function(req, res, next) {

  console.log('\n### Check, if non allowed attributes are used');

  var asset = req.oc.asset;
  for (var i = 0; i < config.bad_asset_attributes.length; i++) {
    var a = config.bad_asset_attributes[i];
    if(asset[a]) {
      res.statusCode = 400;
      res.send('Asset attribute ' + bad_attribues[i] + ' in payload not allowed!');
      return;
    }
  }

  next();
};

var typeIso8601 = 'urn:oc:attributeType:ISO8601';

validation.checkValidityOfAssetTimeInstant = function(req, res, next) {

  console.log('\n### Check, if ISO8601 is correct');

  var asset = req.oc.asset;
  var timeInstant = asset.TimeInstant;

  if(!timeInstant) {
      res.statusCode = 400;
      res.send('Asset attribute TimeInstant in payload not found!');
      return;
  } else {
    // verify the type
    var type = timeInstant.type;
    if(type != typeIso8601) {
      res.statusCode = 400;
      res.send('Asset attribute TimeInstant.type must be ' + typeIso8601);
      return;
    }

    // verify the value
    var value = timeInstant.value;

    // Z at the end is UTC!
    // Verify value, e.g., `2013-12-31T23:59:59Z`
    /*
    var moment = require('moment');

    var pattern = "YYYY-MM-DDTHH:mm:ss";
    var pattern2 = "YYYY-MM-DDTHH:mm:ssZ";

    var a = moment("2013-12-31T23:59:59", pattern, true).isValid();
    console.log(a);

    var b = moment("2013-12-31T23:59:59Z", pattern2, true).isValid();
    console.log(b);

    var c = moment("2013-12-31T23:59:59+0100", pattern, true).isValid();
    console.log(c);

    var d = moment("2013-12-31T23:59:59+01:00", pattern, true).isValid();
    console.log(d);

    var e = moment("2013-12-31T23:59:59+ABC", pattern, true).isValid();
    console.log(e);

    if(!moment(value).isValid()) {
      res.statusCode = 400;
      res.send('Asset attribute TimeInstant.value is not valid!');
      return;
    }
    */

    next();
  }

};


validation.checkValidityOfAssetType = function(req, res, next) {

  console.log('\n### Check the validity of the Asset Type');

  var asset = req.oc.asset;
  var item_type = asset.type;
  var allowedPrefix = 'urn:oc:entityType:';

  // (e) Check, if the prefix of the asset is correct
  if(!item_type.startsWith(allowedPrefix)) {
    res.statusCode = 400;
    res.send('asset.type prefix must be ' + allowedPrefix);
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
      console.log('Asset type found!');
      next();
    } else {

      // If the assed cannot be found, we inform the `OrganiCity Platform Management API` about it

      // Remove the prefix before posting
      var assetName = item_type.substring(allowedPrefix.length);

      console.log('Asset unknown. Inform `OrganiCity Platform Management API` about the new asset type: `', assetName, '`');

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
        next();
      });
    }
  }, errorHandler(res));
};

validation.addFiWareSignature = function(req, res, next) {
  console.log('\n### Add FIWARE signature.');
  req.headers['Fiware-Service'] = 'organicity';
  req.headers['Fiware-ServicePath'] = '/';
  console.log('done');
  next();
};

// Finally, Call the configured server
validation.callFinalServer = function(req, res, next){

  console.log('\n### Forward message to the configured server.');

  // Add x-forwarded-for header
  req.headers = httpClient.getClientIp(req, req.headers);

  var options = {
    method: req.method,
    headers: req.headers,
    protocol: config.application_endpoint.protocol,
    host: config.application_endpoint.host,
    port: config.application_endpoint.port,
    path: req.url
  };

  //
  httpClient.sendData(options, req.oc.asset, res, function(status, responseText, headers) {
    res.oc = {
      statusCode : status,
      headers : headers,
      responseText : responseText
    }
    next();
  });
};

validation.callNotificationProxy = function(req, res, next) {

  if(config.nofification_proxy) {
    console.log('\n### Call Nofication Proxy');

    var options = {
      method: req.method,
      headers: req.headers,
      protocol: config.nofification_proxy.protocol,
      host: config.nofification_proxy.host,
      port: config.nofification_proxy.port,
      path: req.url
    };

    //
    httpClient.sendData(options, undefined, res, function(status, responseText, headers) {
      next();
    }, function(status, responseText, headers) {
      next();
    });

  } else {
    // Skip notification proxy
    next();
  }

};

validation.decreaseExperimentQuota = function(req, res, next) {

  console.log('\n### Decrease the Experiment Quota');

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

  httpClient.sendData(optionsCall, undefined, res, next, errorHandler(res));
}

validation.increaseExperimentQuota = function(req, res, next) {
  console.log('\n### Increase the Experiment Quota');

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

  httpClient.sendData(optionsCall, undefined, res, next, errorHandler(res));
};

validation.doesSiteHaveQuota = function (req, res, next) {

  console.log('\n### Does site have quota?');

  var optionsCall = {
    protocol: config.platform_management_api.protocol,
    host: config.platform_management_api.host,
    port: config.platform_management_api.port,
    path: '/v1/sites/' + req.oc.sitename,
    method: 'GET',
    headers : {
      'authorization' : 'Bearer ' + req.oc.access_token
    }
  };

  httpClient.sendData(optionsCall, undefined, res, function(status, responseText, headers) {
    var responseJson = JSON.parse(responseText);
    var quota = responseJson.remQuota;
    console.log('Quota: ', quota);
    if(quota > 0) {
      next();
    } else {
      res.statusCode = 400;
      res.send('The site reached the quota!');
    }
  });
};

validation.increaseSiteQuota = function(req, res, next) {
  console.log('\n### Increase Site Quota');
  var optionsCall = {
    protocol: config.platform_management_api.protocol,
    host: config.platform_management_api.host,
    port: config.platform_management_api.port,
    path: '/v1/sites/' + req.oc.sitename + '/quota/increment',
    method: 'GET',
    headers : {
      'authorization' : 'Bearer ' + req.oc.access_token
    }
  };

  httpClient.sendData(optionsCall, undefined, res, function(status, responseText, headers) {
    next();
  });
};

validation.decreaseSiteQuota = function(req, res, next) {
  console.log('\n### Decrease Site Quota');

  var optionsCall = {
    protocol: config.platform_management_api.protocol,
    host: config.platform_management_api.host,
    port: config.platform_management_api.port,
    path: '/v1/sites/' + req.oc.sitename + '/quota/decrement',
    method: 'GET',
    headers : {
      'authorization' : 'Bearer ' + req.oc.access_token
    }
  };

  httpClient.sendData(optionsCall, undefined, res, function(status, responseText, headers) {
    next();
  });
};

validation.addSitePrivacy = function(req, res, next) {
  console.log('\n### Add Site Privacy');

  var addPrivacy = function (privacy) {
    req.oc.asset['access:scope'] = {
      "type": "urn:oc:attributeType:access:scope",
      "value": privacy
    }
    next();
  }

  if(req.oc.sitename === 'experimenters') {
    // get /emscheck/assets-public/{expId}
    console.log('Get privacy from Luis');
    var assetId = req.oc.assetId;
    var assetIdParts = assetId.split(':');
    var expId = assetIdParts[5];

    var optionsCall = {
      protocol: config.experiment_management_api.protocol,
      host: config.experiment_management_api.host,
      port: config.experiment_management_api.port,
      path: '/emscheck/assets-public/' + expId,
      method: 'GET',
      headers : {
        'authorization' : 'Bearer: ' + req.oc.access_token
      }
    };

    httpClient.sendData(optionsCall, undefined, res, function(status, responseText, headers) {
      // The experiment has _public_ assets
      addPrivacy('public');
    }, function(status, responseText, headers) {
      // The experiment has _private_ assets
      addPrivacy('private');
    });

  } else {
    addPrivacy('public');
  }
};

validation.sendResponse = function(req, res, next) {
  console.log('\n### Send response');
  // Prepare the response
  res.statusCode = res.oc.statusCode;
  for (var idx in res.oc.headers) {
      var header = res.oc.headers[idx];
      res.setHeader(idx, res.oc.headers[idx]);
  }
  res.send(res.oc.responseText);
};

validation.default = function(req, res, next) {
  res.statusCode = 500;
  res.send('Internal Pipline error');
};

module.exports = validation;
