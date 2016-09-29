var validation = require('./validation');

var log = require('./../lib/logger').logger.getLogger("Root");

var ChainsOfResponsibility = (function() {

  var chains = {
    central : {
      post : [
        validation.init,
        validation.rolehandler(['ocsite']),
        validation.checkSiteToken,
        validation.checkHeaderFiware,
        validation.getAssetFromBody,
        validation.checkValidityOfSiteAsset,
        validation.getAccessToken,
        validation.doesSiteHaveQuota,
        validation.addSitePrivacy,
        validation.callFinalServer,
        validation.decreaseSiteQuota,
        validation.sendResponse
      ],
      delete : [
        validation.init,
        validation.rolehandler(['ocsite']),
        validation.checkSiteToken,
        validation.checkHeaderFiware,
        validation.getAccessToken,
        validation.checkValidityOfSiteAssetId,
        validation.callFinalServer,
        validation.increaseSiteQuota,
        validation.sendResponse
      ],
      get : [
        validation.init,
        validation.rolehandler(['ocsite']),
        validation.checkSiteToken,
        validation.checkHeaderFiware,
        validation.checkValidityOfSiteAssetId,
        validation.callFinalServer,
        validation.sendResponse
        ],
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
        //validation.decreaseExperimentQuota, // Only on POST
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
        validation.checkValidityOfExperimentAssetId, // Only on GET/PUT/DELETE
        validation.addFiWareSignature,
        validation.callFinalServer,
        //validation.increaseExperimentQuota, // Only on DELETE
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
        validation.checkValidityOfExperimentAssetId, // Only on GET/PUT/DELETE
        validation.addFiWareSignature,
        validation.callFinalServer,
        validation.sendResponse
      ],
      put : [
        validation.default
        /*
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
        */
      ]
    }
  };

  //console.log(chains);

  return chains;

})();

module.exports = ChainsOfResponsibility;
