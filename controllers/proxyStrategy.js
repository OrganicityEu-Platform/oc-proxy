var validation = require('./validation');

var log = require('./../lib/logger').logger.getLogger("Root");

var ProxyStrategy = (function() {

  /*
    var strategy = [
      validation.init,
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
      validation.checkValidityOfAssetId, // Only on GET/PUT/DELETE
      validation.checkValidityOfAsset, // Only on POST
      validation.addFiWareSignature,
      validation.callFinalServer,
      validation.decreaseQuota, // Only on POST
      validation.increaseQuota, // Only on DELETE
      validation.sendResponse
    ];
    */

    return {
      central : {
        post : [
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
          validation.checkHeaderFiWare,
          validation.printHeader,
          validation.getAccessToken,
          validation.isSubParticipantExperimenterOfExperiment,
          validation.doesApplicationbelongToAnExperiment,
          validation.isExperimentRunning,
          validation.doesExperimentHaveQuota, // Only on POST
          validation.checkValidityOfAsset, // Only on POST
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
          validation.checkHeaderFiWare,
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
          validation.checkHeaderFiWare,
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
          validation.checkHeaderFiWare,
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

module.exports = ProxyStrategy;
