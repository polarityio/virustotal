polarity.export = PolarityComponent.extend({
  details: Ember.computed.alias('block.data.details'),
  timezone: Ember.computed('Intl', function () {
    return Intl.DateTimeFormat().resolvedOptions().timeZone;
  }),
  maxResolutionsToShow: 20,
  maxUrlsToShow: 20,
  showScanResults: false,
  showDetectedUrls: false,
  showResolutions: false,
  domainVirusTotalLink: '',
  ipVirusTotalLink: '',
  numUrlsShown: 0,
  numResolutionsShown: 0,
  redThreat: '#ed2e4d',
  greenThreat: '#7dd21b',
  yellowThreat: '#ffc15d',
  /**
   * Radius of the ticScore circle
   */
  threatRadius: 15,
  /**
   * StrokeWidth of the ticScore circle
   */
  threatStrokeWidth: 2,
  elementRadius: 20,
  elementStrokeWidth: 4,

  elementColor: Ember.computed('result.domain_risk.risk_score', function () {
    return this._getThreatColor((this.details.positives / this.details.total) * 100);
  }),

  elementStrokeOffset: Ember.computed(
    'result.domain_risk.risk_score',
    'elementCircumference',
    function () {
      return this._getStrokeOffset(this.details.positives, this.elementCircumference);
    }
  ),

  threatCircumference: Ember.computed('threatRadius', function () {
    return 2 * Math.PI * this.get('threatRadius');
  }),

  elementCircumference: Ember.computed('elementRadius', function () {
    return 2 * Math.PI * this.get('elementRadius');
  }),
  _getStrokeOffset(ticScore, circumference) {
    let progress = ticScore / this.details.total;
    return circumference * (1 - progress);
  },
  _getThreatColor(ticScore) {
    if (ticScore >= 50) {
      return this.get('redThreat');
    } else if (ticScore >= 35) {
      return this.get('yellowThreat');
    } else {
      return this.get('greenThreat');
    }
  },
  init() {
    this.set('showScanResults', this.get('details.total') < 15);
    this.set(
      'domainVirusTotalLink',
      'https://www.virustotal.com/gui/domain/' +
        this.get('block.entity.value') +
        '/relations'
    );
    this.set(
      'ipVirusTotalLink',
      'https://www.virustotal.com/gui/ip-address/' +
        this.get('block.entity.value') +
        '/relations'
    );
    this.set(
      'numUrlsShown',
      Math.min(this.get('maxUrlsToShow'), this.get('details.detectedUrls.length'))
    );
    this.set(
      'numResolutionsShown',
      Math.min(this.get('maxResolutionsToShow'), this.get('details.resolutions.length'))
    );

    this._super(...arguments);
  },
  actions: {
    toggleShowScanResults: function () {
      this.toggleProperty(`showScanResults`);
      this.get('block').notifyPropertyChange('data');
    },
    toggleShowDetectedUrls: function () {
      this.toggleProperty(`showDetectedUrls`);
      this.get('block').notifyPropertyChange('data');
    },
    toggleShowResolutions: function () {
      this.toggleProperty(`showResolutions`);
      this.get('block').notifyPropertyChange('data');
    }
  }
});
