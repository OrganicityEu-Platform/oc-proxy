var validation = require('./validation');

var log = require('./../lib/logger').logger.getLogger("Root");

var ChainsOfResponsibility = (function() {

    return {
      central : {
        post : [
          validation.init,
          validation.rolehandler(['ocsite']),
          validation.checkHeaderFiware,
          validation.getAssetFromBody,
          validation.checkValidityOfSiteAsset,
          validation.callFinalServer,
          validation.sendResponse
        ],
        delete : [validation.default],
        get : [validation.default],
        put : [validation.default]
      },
      experimenter : {
        post : [
          validation.init,
          validation.rolehandler(['experimenter', 'participant']),
          validation.checkHeaderOrganicityApplication,
          validation.checkHeaderOrganicityExperiment,
          validation.checkHeaderAuthSub,
          validation.checkHeaderAccept,
          validation.checkHeaderContentType, // Only on POST
          validation.checkHeaderFiwareAbstinence,
          validation.printHeader,
          validation.getAccessToken,
          validation.isSubParticipantExperimenterOfExperiment,
          validation.doesApplicationbelongToAnExperiment,
          validation.isExperimentRunning,
          validation.doesExperimentHaveQuota, // Only on POST
          validation.getAssetFromBody,
          validation.checkValidityOfExperimenterAsset, // Only on POST
          validation.addFiWareSignature,
          validation.callFinalServer,
          //validation.decreaseQuota, // Only on POST
          validation.sendResponse
        ],
        delete : [
          validation.init,
          validation.rolehandler(['experimenter']),
          validation.checkHeaderOrganicityApplication,
          validation.checkHeaderOrganicityExperiment,
          validation.checkHeaderAuthSub,
          validation.checkHeaderAccept,
          validation.checkHeaderFiwareAbstinence,
          validation.printHeader,
          validation.getAccessToken,
          validation.isSubParticipantExperimenterOfExperiment,
          validation.doesApplicationbelongToAnExperiment,
          validation.isExperimentRunning,
          validation.checkValidityOfAssetId, // Only on GET/PUT/DELETE
          validation.addFiWareSignature,
          validation.callFinalServer,
          //validation.increaseQuota, // Only on DELETE
          validation.sendResponse
        ],
        get : [
          validation.init,
          validation.rolehandler(['experimenter']),
          validation.checkHeaderOrganicityApplication,
          validation.checkHeaderOrganicityExperiment,
          validation.checkHeaderAuthSub,
          validation.checkHeaderAccept,
          validation.checkHeaderFiwareAbstinence,
          validation.printHeader,
          validation.getAccessToken,
          validation.isSubParticipantExperimenterOfExperiment,
          validation.doesApplicationbelongToAnExperiment,
          validation.isExperimentRunning,
          validation.checkValidityOfAssetId, // Only on GET/PUT/DELETE
          validation.addFiWareSignature,
          validation.callFinalServer,
          validation.sendResponse
        ],
        put : [
          validation.init,
          validation.rolehandler(['experimenter']),
          validation.checkHeaderOrganicityApplication,
          validation.checkHeaderOrganicityExperiment,
          validation.checkHeaderAuthSub,
          validation.checkHeaderAccept,
          validation.checkHeaderFiwareAbstinence,
          validation.printHeader,
          validation.getAccessToken,
          validation.isSubParticipantExperimenterOfExperiment,
          validation.doesApplicationbelongToAnExperiment,
          validation.isExperimentRunning,
          validation.checkValidityOfAssetId, // Only on GET/PUT/DELETE
          validation.addFiWareSignature,
          validation.callFinalServer,
          validation.sendResponse
        ]
      }
    }


})();

module.exports = ChainsOfResponsibility;
