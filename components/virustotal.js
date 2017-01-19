polarity.export = PolarityComponent.extend({
    classNames: ['virustotal-details-block'],
    // // Resolutions are for IP addresses
    // MAX_RESOLUTIONS_IN_SUMMARY: 3,
    // // Scans are an antivirus product scan on a file hash
    // MAX_SCANS_IN_SUMMARY: 3,
    maxResolutionsToShow: 10,
    maxUrlsToShow: 10,
    // // Each of the summary blocks is not wrapped in a containing element so that they can
    // // all be floated together but still be managed as separate components.
    // //tagName: 'span',
    // additionalDataCount: 0,
    // virusTotalType: Ember.computed('block.data.details', function(){
    //     return this._getReportType();
    // }),
    // summarizedData: Ember.computed('block.data.details', function(){
    //     var type = this._getReportType();
    //
    //     if(type === 'ip'){
    //         return this._computeIpReportSummarizedData();
    //     }else if(type === 'file'){
    //         return this._computeFileReportSummarizedData();
    //     }
    //     return Ember.Object.create({
    //         type: 'NA'
    //     });
    // }),
    numResolutionsShown: Ember.computed('maxResolutionsToShow', 'block.data.details.resolutions.length', function(){
        var maxResolutionsToShow = this.get('maxResolutionsToShow');
        var totalResolutions = this.get('block.data.details.resolutions.length');

        if(maxResolutionsToShow < totalResolutions){
            return maxResolutionsToShow;
        }
        return totalResolutions;
    }),
    numUrlsShown: Ember.computed('maxUrlsToShow', 'block.data.details.detectedUrls.length', function(){
        var maxUrlsToShow = this.get('maxUrlsToShow');
        var totalUrls = this.get('block.data.details.detectedUrls.length');

        if(maxUrlsToShow < totalUrls){
            return maxUrlsToShow;
        }
        return totalUrls;
    }),
    ipVirusTotalLink: Ember.computed('block.entity.value', function(){
        var entityName = this.get('block.entity.value');
        return 'https://www.virustotal.com/en/ip-address/' + entityName + '/information/';
    }),
    // _computeFileReportSummarizedData: function(){
    //     var data = this.get('block.data.details');
    //     var scansObj = this.get('block.data.details.scans');
    //     var scans = Object.keys(scansObj).map(key => scansObj[key]);
    //     var summarizedData = Ember.Object.create({
    //         type: 'file',
    //         detectionRate: data.positives + ' detects /' + data.total
    //     });
    //
    //     var additionalData = scans.length - this.MAX_SCANS_IN_SUMMARY;
    //     if(additionalData > 0){
    //         this.set('additionalDataCount', additionalData);
    //     }
    //
    //     return summarizedData;
    // },
    // _computeIpReportSummarizedData: function(){
    //     //console.info("BLOCK DATA:");
    //     //console.info(JSON.stringify(this.get('block.data.details'), null, 4));
    //     var resolutions = this.get('block.data.details.resolutions');
    //     var detectedUrls = this.get('block.data.details.detectedUrls');
    //     var detectedCommunicatingSamples = this.get('block.data.details.detectedCommunicatingSamples');
    //     var detectedDownloadedSamples = this.get('block.data.details.detectedDownloadedSamples');
    //     var detectedReferrerSamples = this.get('block.data.details.detectedReferrerSamples');
    //
    //     var summarizedData = Ember.Object.create({
    //         type: 'ip'
    //     });
    //
    //     var overallPositives = 0;
    //     var overallTotal = 0;
    //     var detectedUrlsPositive = 0;
    //     var detectedUrlsTotal = 0;
    //     if(Array.isArray(detectedUrls)) {
    //         for (var i = 0; i < detectedUrls.length; i++) {
    //             overallPositives += detectedUrls[i].positives;
    //             overallTotal += detectedUrls[i].total;
    //             detectedUrlsTotal += detectedUrls[i].total;
    //             detectedUrlsPositive += detectedUrls[i].positives;
    //         }
    //     }
    //
    //     var detectedCommunicatingPositive = 0;
    //     var detectedCommunicatingTotal = 0;
    //     if(Array.isArray(detectedCommunicatingSamples)) {
    //         for (let i = 0; i < detectedCommunicatingSamples.length; i++) {
    //             overallPositives += detectedCommunicatingSamples[i].positives;
    //             overallTotal += detectedCommunicatingSamples[i].total;
    //             detectedCommunicatingPositive += detectedCommunicatingSamples[i].positives;
    //             detectedCommunicatingTotal += detectedCommunicatingSamples[i].total;
    //         }
    //     }
    //
    //
    //     var detectedDownloadingPositive = 0;
    //     var detectedDownloadingTotal = 0;
    //     if(Array.isArray(detectedDownloadedSamples)) {
    //         for (let i = 0; i < detectedDownloadedSamples.length; i++) {
    //             overallPositives += detectedDownloadedSamples[i].positives;
    //             overallTotal += detectedDownloadedSamples[i].total;
    //             detectedDownloadingPositive += detectedDownloadedSamples[i].positives;
    //             detectedDownloadingTotal += detectedDownloadedSamples[i].total;
    //         }
    //     }
    //
    //     var detectedReferrerPositive = 0;
    //     var detectedReferrerTotal = 0;
    //     if(Array.isArray(detectedReferrerSamples)) {
    //         for (let i = 0; i < detectedReferrerSamples.length; i++) {
    //             overallPositives += detectedReferrerSamples[i].positives;
    //             overallTotal += detectedReferrerSamples[i].total;
    //             detectedReferrerPositive += detectedReferrerSamples[i].positives;
    //             detectedReferrerTotal += detectedReferrerSamples[i].total;
    //         }
    //     }
    //
    //     summarizedData.set('overallPositives', overallPositives);
    //     summarizedData.set('overallTotal', overallTotal);
    //     if(overallTotal === 0){
    //         summarizedData.set('overallPercent', 'NA');
    //     }else{
    //         summarizedData.set('overallPercent', ((overallPositives / overallTotal) * 100).toFixed(0) + '%');
    //     }
    //
    //     summarizedData.set('detectedUrlsPositive', detectedUrlsPositive);
    //     summarizedData.set('detectedUrlsTotal', detectedUrlsTotal);
    //     if(detectedUrlsTotal === 0){
    //         summarizedData.set('detectedUrlsPercent', 'NA');
    //     }else{
    //         summarizedData.set('detectedUrlsPercent', ((detectedUrlsPositive / detectedUrlsTotal) * 100).toFixed(0) + '%');
    //     }
    //
    //     summarizedData.set('detectedCommunicatingPositive', detectedCommunicatingPositive);
    //     summarizedData.set('detectedCommunicatingTotal', detectedCommunicatingTotal);
    //     if(detectedCommunicatingTotal === 0){
    //         summarizedData.set('detectedCommunicatingPercent', 'NA');
    //     }else{
    //         summarizedData.set('detectedCommunicatingPercent', ((detectedCommunicatingPositive / detectedCommunicatingTotal) * 100).toFixed(0) + '%');
    //     }
    //
    //
    //     summarizedData.set('detectedDownloadingPositive', detectedDownloadingPositive);
    //     summarizedData.set('detectedDownloadingTotal', detectedDownloadingTotal);
    //     if(detectedDownloadingTotal === 0){
    //         summarizedData.set('detectedDownloadingPercent', 'NA');
    //     }else{
    //         summarizedData.set('detectedDownloadingPercent', ((detectedDownloadingPositive / detectedDownloadingTotal) * 100).toFixed(0) + '%');
    //     }
    //
    //     summarizedData.set('detectedReferrerPositive', detectedReferrerPositive);
    //     summarizedData.set('detectedReferrerTotal', detectedReferrerTotal);
    //     if(detectedReferrerTotal === 0){
    //         summarizedData.set('detectedReferrerPercent', 'NA');
    //     }else{
    //         summarizedData.set('detectedReferrerPercent', ((detectedReferrerPositive / detectedReferrerTotal) * 100).toFixed(0) + '%');
    //     }
    //
    //     summarizedData.set('numResolutions', resolutions.length);
    //
    //     return summarizedData;
    // },
    // /**
    //  * VirusTotal reports can be for files (hashes) or ip addresses.  We infer which type it is
    //  * based on the expected presence of certain properties on the data.  *
    //  *
    //  * @private
    //  * @return string 'file' for file report, 'ip' for ip report, 'NA' for invalid
    //  */
    // _getReportType: function(){
    //     var data = this.get('block.data.details');
    //     if(typeof(data.scans) !== 'undefined'){
    //         return 'file';
    //     }else if(typeof(data.resolutions) !== 'undefined'){
    //         return 'ip';
    //     }
    //
    //     return 'NA';
    // }
});
