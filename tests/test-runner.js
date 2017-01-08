'use strict';

let virustotal = require('../integration');

let options = {
    apikey: '2607441d2e583edd89cbd971dfc29c65a9771d85a30edd62d781f458f5a54038'
};

virustotal.doLookup([{
    value: 'fd904addbdfe548c22ffa5223ed9eee7',
    isHash: true
}], options, function(err, result){
   if(err){
       console.info("ERRORS:");
       console.info(JSON.stringify(err, null, 4));
   }else{
       console.info("RESULTS:");
       console.info(JSON.stringify(result, null, 4));
   }
});
