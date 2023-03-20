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
  behaviorSummary: null,
  expandedWhoisMap: Ember.computed.alias('block.data.details.expandedWhoisMap'),
  communityScoreWidth: Ember.computed('details.reputation', function () {
    let reputation = this.get('details.reputation');
    // clamp reputation to between -100 and 100
    if (reputation > 100) {
      reputation = 100;
    }
    if (reputation <= -100) {
      reputation = -100;
    }

    // scale reputation which goes from -100 to 100 into the range 0 to 100
    return 100 * ((reputation + 100) / 200);
  }),
  communityScoreIcon: Ember.computed('details.reputation', function () {
    let reputation = this.get('details.reputation');
    if (reputation === 0) {
      return 'map-marker-question';
    }
    if (reputation > 0) {
      return 'map-marker-check';
    }

    return 'map-marker-times';
  }),
  communityScoreColorClass: Ember.computed('details.reputation', function () {
    let reputation = this.get('details.reputation');
    if (reputation === 0) {
      return 'score-marker-icon p-grey';
    }
    if (reputation < 0) {
      return 'score-marker-icon p-red';
    }
    return 'score-marker-icon p-green';
  }),
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
  _getStrokeOffset (ticScore, circumference) {
    let progress = ticScore / this.details.total;
    return circumference * (1 - progress);
  },
  _getThreatColor (ticScore) {
    if (ticScore > 0) {
      return this.get('redThreat');
    } else {
      return this.get('greenThreat');
    }
  },
  init () {
    this.set(
      'showScanResults',
      this.get('block.userOptions.showNoDetections') === false
        ? this.get('details.positiveScans.length') < 15
        : this.get('details.total') < 15
    );
    this.set(
      'numUrlsShown',
      Math.min(this.get('maxUrlsToShow'), this.get('details.detectedUrls.length'))
    );
    this.set(
      'numResolutionsShown',
      Math.min(this.get('maxResolutionsToShow'), this.get('details.resolutions.length'))
    );
    if (!this.get('block._state')) {
      this.set('block._state', {});
    }

    if (this.get('details.names.length') <= 10) {
      this.set('block._state.showNames', true);
    }

    this._super(...arguments);
  },
  getBehaviors: function () {
    const payload = {
      action: 'GET_BEHAVIORS',
      entity: this.get('block.entity')
    };
    this.set('block._state.errorBehaviors', '');
    this.set('block._state.loadingBehaviors', true);
    this.sendIntegrationMessage(payload)
      .then((behaviorSummary) => {
        if (behaviorSummary) {
          this.set('block.data.details.behaviorSummary', behaviorSummary);
          this.set(
            'showRegistryKeys',
            typeof this.get('details.behaviorSummary.registry_keys_opened') ===
              'undefined'
          );
          this.set('showFilesOpened', !this.get('details.behaviorSummary.files_opened'));
          this.set('block._state.loadedBehaviors', true);
        }
      })
      .catch((err) => {
        this.set('block._state.errorBehaviors', JSON.stringify(err, null, 4));
      })
      .finally(() => {
        this.set('block._state.loadingBehaviors', false);
      });
  },
  getWhois: function () {
    const payload = {
      action: 'GET_WHOIS',
      entity: this.get('block.entity')
    };
    this.set('block._state.errorWhois', '');
    this.set('block._state.loadingWhois', true);
    this.sendIntegrationMessage(payload)
      .then((historicalWhoIs) => {
        this.set('block.data.details.historicalWhoIs', historicalWhoIs);
        this.set('expandedWhoisMap', []);
        // If there is no data we expand the whois section automatically
        // to show a "no results" message
        if (historicalWhoIs.length === 0) {
          this.set('showHistoricalWhois', true);
        }
        this.set('block._state.loadedWhois', true);
      })
      .catch((err) => {
        this.set('block._state.errorWhois', JSON.stringify(err, null, 4));
      })
      .finally(() => {
        this.set('block._state.loadingWhois', false);
      });
  },
  getRelations: function () {
    const payload = {
      action: 'GET_RELATIONS',
      entity: this.get('block.entity')
    };
    this.set('block._state.errorRelations', '');
    this.set('block._state.loadingRelations', true);
    this.sendIntegrationMessage(payload)
      .then((referenceFiles) => {
        this.set('block.data.details.referenceFiles', referenceFiles);
        // If there is no data we expand the whois section automatically
        // to show a "no results" message
        if (referenceFiles.length === 0) {
          this.set('showFilesReferring', true);
        }
        this.set('block._state.loadedRelations', true);
        this.get('block').notifyPropertyChange('data');
      })
      .catch((err) => {
        this.set('block._state.errorRelations', JSON.stringify(err, null, 4));
      })
      .finally(() => {
        this.set('block._state.loadingRelations', false);
      });
  },
  actions: {
    /**
     * Change data tab.  valid tab names are:
     * detection
     * details
     * fileNames -- requires fileName data
     * behaviorSummary -- requires behavior data
     * relations -- requires relations and whois data
     * @param tabName
     */
    changeTab: function (tabName) {
      this.set('activeTab', tabName);
      switch (tabName) {
        // relations tab requires relations and whois data
        case 'relations':
          // Make sure we only load the data once
          if (!this.get('block._state.loadedWhois')) {
            this.getWhois();
          }
          if (!this.get('block._state.loadedRelations')) {
            this.getRelations();
          }
          break;
        case 'behaviorSummary':
          if (!this.get('block._state.loadedBehaviors')) {
            this.getBehaviors();
          }
          break;
      }
    },
    toggleShowResults: function (resultType) {
      this.toggleProperty(resultType);
    },
    expandWhoIsRow: function (index) {
      this.set(`expandedWhoisMap.${index}`, !this.get(`expandedWhoisMap.${index}`));
    },
    copyReferringFiles: function () {
      const content = this.get('details.referenceFiles');
      let clipboardContent = '';
      content.forEach((file) => {
        clipboardContent += file.name + '\n';
      });
      navigator.clipboard.writeText(clipboardContent);
    }
  }
});
