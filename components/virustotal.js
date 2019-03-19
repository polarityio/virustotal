polarity.export = PolarityComponent.extend({
  timezone: Ember.computed('Intl', function() {
    return Intl.DateTimeFormat().resolvedOptions().timeZone;
  }),
  maxResolutionsToShow: 10,
  maxUrlsToShow: 10,
  numResolutionsShown: Ember.computed('maxResolutionsToShow', 'block.data.details.resolutions.length', function() {
    let maxResolutionsToShow = this.get('maxResolutionsToShow');
    let totalResolutions = this.get('block.data.details.resolutions.length');

    if (maxResolutionsToShow < totalResolutions) {
      return maxResolutionsToShow;
    }
    return totalResolutions;
  }),
  numUrlsShown: Ember.computed('maxUrlsToShow', 'block.data.details.detectedUrls.length', function() {
    let maxUrlsToShow = this.get('maxUrlsToShow');
    let totalUrls = this.get('block.data.details.detectedUrls.length');

    if (maxUrlsToShow < totalUrls) {
      return maxUrlsToShow;
    }
    return totalUrls;
  }),
  ipVirusTotalLink: Ember.computed('block.entity.value', function() {
    let entityName = this.get('block.entity.value');
    return 'https://www.virustotal.com/en/ip-address/' + entityName + '/information/';
  })
});
