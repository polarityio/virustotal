polarity.export = PolarityComponent.extend({
  details: Ember.computed.alias('block.data.details'),
  timezone: Ember.computed('Intl', function () {
    return Intl.DateTimeFormat().resolvedOptions().timeZone;
  }),
  maxResolutionsToShow: 10,
  maxUrlsToShow: 10,
  numResolutionsShown: Ember.computed('maxResolutionsToShow', 'details.resolutions.length', function () {
    let maxResolutionsToShow = this.get('maxResolutionsToShow');
    let totalResolutions = this.get('details.resolutions.length');

    if (maxResolutionsToShow < totalResolutions) {
      return maxResolutionsToShow;
    }
    return totalResolutions;
  }),
  numUrlsShown: Ember.computed('maxUrlsToShow', 'details.detectedUrls.length', function () {
    let maxUrlsToShow = this.get('maxUrlsToShow');
    let totalUrls = this.get('details.detectedUrls.length');

    if (maxUrlsToShow < totalUrls) {
      return maxUrlsToShow;
    }
    return totalUrls;
  }),
  ipVirusTotalLink: Ember.computed('block.entity.value', function () {
    let entityName = this.get('block.entity.value');
    return 'https://www.virustotal.com/en/ip-address/' + entityName + '/information/';
  }),
  domainVirusTotalLink: Ember.computed('block.entity.value', function () {
    let entityName = this.get('block.entity.value');
    return 'https://www.virustotal.com/en/domain/' + entityName + '/information/';
  })
});
