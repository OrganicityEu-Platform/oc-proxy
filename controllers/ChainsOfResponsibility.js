var validation = require('./validation');

var log = require('./../lib/logger').logger.getLogger("Root");

var ChainsOfResponsibility = (function() {

  var chains = {
    central : {
      post : [
        validation.init,
        validation.logCreate,
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
        //validation.decreaseSiteQuota,
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
        validation.logUpdate,
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
      ],
      status : [
        validation.status
      ]
    },
    experimenter : {
      post : [
        validation.init,
        validation.bearer,
        validation.rolehandler(['experimenter', 'participant']),
        validation.checkHeaderOrganicityApplication,
        validation.checkHeaderOrganicityExperiment,
        validation.checkHeaderAccept,
        validation.checkHeaderContentType,
        validation.checkHeaderFiwareAbstinence,
        validation.printHeader,

        validation.getAccessToken,
        validation.getAssetFromBody,
        validation.checkValidityOfExperimenterAssetIdFromBody,
        validation.canCreateAsset, // EP portal

        validation.checkValidityOfAssetType,

        validation.checkForNonAllowedAttributes,
        validation.checkValidityOfAssetTimeInstant,

        validation.addFiWareSignature,
        validation.addExperimenterSitePrivacy,

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
        validation.checkHeaderAccept,
        validation.checkHeaderFiwareAbstinence,
        validation.printHeader,

        validation.getAccessToken,
        validation.checkValidityOfExperimenterAssetIdFromParam,
        validation.canCreateAsset, // EP portal

        validation.addFiWareSignature,

        validation.callFinalServer,
        validation.callNotificationProxy,
//        validation.increaseExperimentQuota,
        validation.sendResponse
      ],
      get : [
        validation.init,
        validation.bearer,
        validation.rolehandler(['experimenter']),
        validation.checkHeaderOrganicityApplication,
        validation.checkHeaderOrganicityExperiment,
        validation.checkHeaderAccept,
        validation.checkHeaderFiwareAbstinence,
        validation.printHeader,

        validation.getAccessToken,
        validation.checkValidityOfExperimenterAssetIdFromParam,
        validation.canCreateAsset, // EP portal

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
        validation.checkHeaderAccept,
        validation.checkHeaderContentType,
        validation.checkHeaderFiwareAbstinence,
        validation.printHeader,

        validation.getAccessToken,
        validation.getAssetFromBody,
        validation.checkValidityOfExperimenterAssetIdFromParam,
        validation.canCreateAsset, // EP portal

        validation.checkForNonAllowedAttributes,
        validation.checkForNonAllowedAttribute('id'),
        validation.checkForNonAllowedAttribute('type'),
        validation.checkValidityOfAssetTimeInstant,

        validation.addFiWareSignature,
        validation.addExperimenterSitePrivacy,

        validation.callFinalServer,
        validation.fixLocationHeader,
        validation.sendResponse
      ],
      status : [
        validation.status
      ]
    }
  };

  //console.log(chains);

  return chains;

})();

module.exports = ChainsOfResponsibility;
