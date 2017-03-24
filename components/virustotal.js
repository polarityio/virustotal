polarity.export = PolarityComponent.extend({
    classNames: ['virustotal-details-block'],
    maxResolutionsToShow: 10,
    maxUrlsToShow: 10,
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
    })
});
