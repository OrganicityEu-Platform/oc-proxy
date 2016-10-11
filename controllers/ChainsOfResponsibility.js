var validation = require('./validation');

var log = require('./../lib/logger').logger.getLogger("Root");

var ChainsOfResponsibility = (function() {

  var chains = {
    central : {
      post : [
        validation.init,
        validation.bearer,
        validation.rolehandler(['ocsite']),
        validation.checkSiteToken,
        validation.checkHeaderFiware,
        validation.getAccessToken,
        validation.getAssetFromBody,
        validation.checkValidityOfSiteAssetIdFromBody,
        validation.checkValidityOfAssetTimeInstant,
        validation.doesSiteHaveQuota,
        validation.addSitePrivacy,
        validation.callFinalServer,
        validation.decreaseSiteQuota,
        validation.sendResponse
      ],
      delete : [
        validation.init,
        validation.bearer,
        validation.rolehandler(['ocsite']),
        validation.checkSiteToken,
        validation.checkHeaderFiware,
        validation.getAccessToken,
        validation.checkValidityOfSiteAssetIdFromParam,
        validation.callFinalServer,
        validation.increaseSiteQuota,
        validation.sendResponse
      ],
      get : [
        validation.init,
        validation.bearer,
        validation.rolehandler(['ocsite']),
        validation.checkSiteToken,
        validation.checkHeaderFiware,
        validation.checkValidityOfSiteAssetIdFromParam,
        validation.callFinalServer,
        validation.sendResponse
        ],
      put : [
        validation.init,
        validation.bearer,
        validation.rolehandler(['ocsite']),
        validation.checkSiteToken,
        validation.checkHeaderFiware,
        validation.getAccessToken,
        validation.getAssetFromBody,
        validation.checkValidityOfSiteAssetIdFromParam,
        validation.checkForNonAllowedAttribute('id'),
        validation.checkForNonAllowedAttribute('type'),
        validation.checkValidityOfAssetTimeInstant,
        validation.addSitePrivacy,
        validation.callFinalServer,
        validation.sendResponse
      ]
    },
    experimenter : {
      post : [
        validation.init,
        validation.bearer,
        validation.rolehandler(['experimenter', 'participant']),
        validation.checkHeaderOrganicityApplication,
        validation.checkHeaderOrganicityExperiment,
        validation.checkHeaderAuthSub,
        validation.checkHeaderAccept,
        validation.checkHeaderContentType,
        validation.checkHeaderFiwareAbstinence,
        validation.printHeader,
        validation.getAccessToken,
        validation.isSubParticipantExperimenterOfExperiment,
        validation.doesApplicationbelongToAnExperiment,
        validation.isExperimentRunning,
        validation.doesExperimentHaveQuota,
        validation.getAssetFromBody,
        validation.checkValidityOfExperimenterAssetIdFromBody,
        validation.checkValidityOfAssetType,
        validation.checkForNonAllowedAttributes,
        validation.checkValidityOfAssetTimeInstant,
        validation.addFiWareSignature,
        validation.callFinalServer,
        validation.decreaseExperimentQuota,
        validation.fixLocationHeader,
        validation.sendResponse
      ],
      delete : [
        validation.init,
        validation.bearer,
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
        validation.checkValidityOfExperimenterAssetIdFromParam,
        validation.addFiWareSignature,
        validation.callFinalServer,
        validation.callNotificationProxy,
        validation.increaseExperimentQuota,
        validation.sendResponse
      ],
      get : [
        validation.init,
        validation.bearer,
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
        validation.checkValidityOfExperimenterAssetIdFromParam,
        validation.addFiWareSignature,
        validation.callFinalServer,
        validation.sendResponse
      ],
      put : [
        validation.init,
        validation.bearer,
        validation.rolehandler(['experimenter', 'participant']),
        validation.checkHeaderOrganicityApplication,
        validation.checkHeaderOrganicityExperiment,
        validation.checkHeaderAuthSub,
        validation.checkHeaderAccept,
        validation.checkHeaderContentType,
        validation.checkHeaderFiwareAbstinence,
        validation.printHeader,
        validation.getAccessToken,
        validation.isSubParticipantExperimenterOfExperiment,
        validation.doesApplicationbelongToAnExperiment,
        validation.isExperimentRunning,
        validation.doesExperimentHaveQuota,
        validation.checkValidityOfExperimenterAssetIdFromParam,
        validation.getAssetFromBody,
        validation.checkForNonAllowedAttribute('id'),
        validation.checkForNonAllowedAttribute('type'),
        validation.checkForNonAllowedAttributes,
        validation.checkValidityOfAssetTimeInstant,
        validation.addFiWareSignature,
        validation.callFinalServer,
        validation.sendResponse
      ]
    }
  };

  //console.log(chains);

  return chains;

})();

module.exports = ChainsOfResponsibility;
