var config = require('./../config.js'),
    httpClient = require('./../lib/HTTPClient.js'),
    url = require('url');

require('string.prototype.startswith');

var validation = require('./validation');
var log = require('./../lib/logger').logger.getLogger("Root");

var Root = (function() {


    var dummy = function() {
      console.log('DUMMY CALLED');
    }

    var strategy = [
    validation.checkHeaderOrganicityApplication,
      validation.checkHeaderOrganicityExperiment,
      validation.checkHeaderAuthSub,
      validation.checkHeaderAccept,
      validation.checkHeaderContentType, // Only on POST
      validation.checkHeaderFiWare,
      validation.printHeader,
      validation.getAccessToken,
      validation.isSubParticipantExperimenterOfExperiment,
      validation.doesApplicationbelongToAnExperiment,
      validation.isExperimentRunning,
      validation.doesExperimentHaveQuota, // Only on POST
      validation.checkValidityOfAssetId, // ONLY on GET/PUT/DELETE
      validation.checkValidityOfAsset, // ONLY on POST
      validation.addFiWareSignature,
      validation.callFinalServer,
      validation.decreaseQuota, // ONLY on POST
      validation.increaseQuota, // ONLY on DELETE
      validation.sendResponse,
      dummy
    ];

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

      var nexti = 0;
      var next = (function(req, res, options, body) {
        return function() {
          var i = nexti;
          nexti++;
          strategy[i](req, res, options, body, next);
        }
      })(req, res, options, body);

      req.oc = {};
      next();
    };

    return {
        pep: pep
    }
})();

exports.Root = Root;
