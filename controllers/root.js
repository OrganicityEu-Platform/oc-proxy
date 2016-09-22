var validation = require('./validation');
var log = require('./../lib/logger').logger.getLogger("Root");

var Root = (function() {

    var strategyPost = [
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
      validation.checkValidityOfAssetId, // ONLY on GET/PUT/DELETE
      validation.checkValidityOfAsset, // ONLY on POST
      validation.addFiWareSignature,
      validation.callFinalServer,
      validation.decreaseQuota, // ONLY on POST
      validation.increaseQuota, // ONLY on DELETE
      validation.sendResponse
    ];

    return {
        post: strategyPost
    }
})();

exports.Root = Root;
