polarity.export = PolarityComponent.extend({
  details: Ember.computed.alias('block.data.details'),
  timezone: Ember.computed('Intl', function () {
    return Intl.DateTimeFormat().resolvedOptions().timeZone;
  }),
  maxResolutionsToShow: 20,
  maxUrlsToShow: 20,
  showScanResults: false,
  showFilesReferring: false,
  showHistoricalWhois: false,
  expandedWhoisMap: Ember.computed.alias('block.data.details.expandedWhoisMap'),
  domainVirusTotalLink: '',
  numUrlsShown: 0,
  numResolutionsShown: 0,
  whoIsIpKeys: [
    { key: 'origin' },
    { key: 'role' },
    { key: 'mnt-by' },
    { key: 'admin-c' },
    { key: 'netname' },
    { key: 'NetType' },
    { key: 'address' },
    { key: 'inetnum' },
    { key: 'Ref' },
    { key: 'Parent' },
    { key: 'Nedivange' },
    { key: 'Updated Date', isDate: true },
    { key: 'OrgId' },
    { key: 'OrgAbuseName' },
    { key: 'OrgAbusePhone' },
    { key: 'OrgTechRef' },
    { key: 'OrgTechHandle' },
    { key: 'OrgAbuseRef' },
    { key: 'City' },
    { key: 'StateProv' },
    { key: 'Address' }
  ],
  whoIsDomainKeys: [
    { key: 'Domain Name' },
    { key: 'Name Server' },
    { key: 'Domain Status' },
    { key: 'DNSSEC' },
    { key: 'Creation Date', isDate: true },
    { key: 'Updated Date' },
    { key: 'Registrant Organization' },
    { key: 'Registrant Country' },
    { key: 'Registrant State/Province' },
    { key: 'Registrant Email' },
    { key: 'Registrar' },
    { key: 'Registrar URL' },
    { key: 'Registrar WHOIS Server' },
    { key: 'Registrar IANA ID' },
    { key: 'Registrar Abuse Contact Phone' },
    { key: 'Registrar Abuse Contact Email' },
    { key: 'Registrar Registration Expiration Date', isDate: true },
    { key: 'Registry Domain ID' },
    { key: 'Registry Expiry Date', isDate: true }
  ],
  activeTab: 'detection',
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
    if (ticScore > 0) {
      return this.get('redThreat');
    } else {
      return this.get('greenThreat');
    }
  },
  init() {
    this.set(
      'showRegistryKeys',
      this.get('details.behaviorSummary.registry_keys_opened')
    );
    this.set('showFilesOpened', this.get('details.behaviorSummary.files_opened'));
    this.set('showScanResults', this.get('details.total') < 15);
    this.set(
      'numUrlsShown',
      Math.min(this.get('maxUrlsToShow'), this.get('details.detectedUrls.length'))
    );
    this.set(
      'numResolutionsShown',
      Math.min(this.get('maxResolutionsToShow'), this.get('details.resolutions.length'))
    );
    console.log(this.get('details'));

    this._super(...arguments);
  },
  actions: {
    changeTab: function (tabName) {
      this.set('activeTab', tabName);
    },
    toggleShowResults: function (resultType) {
      this.toggleProperty(resultType);
      this.get('block').notifyPropertyChange('data');
    },
    expandWhoIsRow: function (index) {
      this.set(`expandedWhoisMap.${index}`, !this.get(`expandedWhoisMap.${index}`));
      this.get('block').notifyPropertyChange('data');
    }
  }
});
