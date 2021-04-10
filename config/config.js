module.exports = {
  /**
   * Name of the integration which is displayed in the Polarity integrations user interface
   *
   * @type String
   * @required
   */
  name: 'VirusTotal',
  /**
   * The acronym that appears in the notification window when information from this integration
   * is displayed.  Note that the acronym is included as part of each "tag" in the summary information
   * for the integration.  As a result, it is best to keep it to 4 or less characters.  The casing used
   * here will be carried forward into the notification window.
   *
   * @type String
   * @required
   */
  acronym: 'VT',
  /**
   * Description for this integration which is displayed in the Polarity integrations user interface
   *
   * @type String
   * @optional
   */
  description:
    'VirusTotal Integration for File and IP Address Reports via the v3.0 REST API',
  defaultColor: 'light-pink',
  entityTypes: ['url', 'domain', 'IPv4', 'hash'],
  /**
   * An array of style files (css or less) that will be included for your integration. Any styles specified in
   * the below files can be used in your custom template.
   *
   * @type Array
   * @optional
   */
  styles: ['./styles/virustotal.less'],
  /**
   * Provide custom component logic and template for rendering the integration details block.  If you do not
   * provide a custom template and/or component then the integration will display data as a table of key value
   * pairs.
   *
   * @type Object
   * @optional
   */
  block: {
    component: {
      file: './components/virustotal.js'
    },
    template: {
      file: './templates/virustotal.hbs'
    }
  },
  settings: {
    /**
     * This is an experimental feature designed to reduce the number of lookups made to VirusTotal.  It works
     * by tracking pending lookups and then queuing additional lookups on an indicator until after
     * any pending lookups are returned.
     *
     * Important: You must be running Polarity-Server >= 2.5.0 if you want to set this value to true
     */
    trackPendingLookups: false
  },
  request: {
    // Provide the path to your certFile. Leave an empty string to ignore this option.
    // Relative paths are relative to the VT integration's root directory
    cert: '',
    // Provide the path to your private key. Leave an empty string to ignore this option.
    // Relative paths are relative to the VT integration's root directory
    key: '',
    // Provide the key passphrase if required.  Leave an empty string to ignore this option.
    // Relative paths are relative to the VT integration's root directory
    passphrase: '',
    // Provide the Certificate Authority. Leave an empty string to ignore this option.
    // Relative paths are relative to the VT integration's root directory
    ca: '',
    // An HTTP proxy to be used. Supports proxy Auth with Basic Auth, identical to support for
    // the url parameter (by embedding the auth info in the uri)
    proxy: '',

    rejectUnauthorized: true
  },
  logging: {
    level: 'info', //trace, debug, info, warn, error, fatal
    // Special flag to log per hour unique hash and ip counts to the log file
    // Counts are reset every 24 hours
    logLookupStats: false
  },
  /**
   * Options that are displayed to the user/admin in the Polarity integration user-interface.  Should be structured
   * as an array of option objects.
   *
   * @type Array
   * @optional
   */
  options: [
    {
      key: 'apiKey',
      name: 'VirusTotal API Key',
      description: 'Your VirusTotal API Key',
      default: '',
      type: 'password',
      userCanEdit: true,
      adminOnly: false
    },
    {
      key: 'showNoInfoTag',
      name: 'Show "No Information in VirusTotal"',
      description:
        'If checked, this option will make it so when there are no results in Virus Total it will always display the tag summary "No Information in VirusTotal".',
      default: false,
      type: 'boolean',
      userCanEdit: true,
      adminOnly: false
    },
    {
      key: 'showNoDetections',
      name: 'Show All File Scanner AV Results',
      description:
        'If checked, the integration will show all AV scanner results for files (hashes) even if the AV scanner did not detect the sample as a positive detection.  Default is to show all results.  Uncheck to only show positive AV detections in the scanner results table.',
      default: true,
      type: 'boolean',
      userCanEdit: true,
      adminOnly: false
    },
    {
      key: 'showHashesWithNoDetections',
      name: 'Show Files (Hashes) with No Detections',
      description:
        'If checked, the integration will show results for files that have no positive detections.',
      default: false,
      type: 'boolean',
      userCanEdit: true,
      adminOnly: false
    },
    {
      key: 'showIpsWithNoDetections',
      name: 'Show IP Addresses with No Detections',
      description:
        'If checked, the integration will show results for IP addresses that have no positive detections.  By default, the integration will not show IP reports with no positive detections even if the IP address in question has a resolved hostname. ',
      default: false,
      type: 'boolean',
      userCanEdit: true,
      adminOnly: false
    },
    {
      key: 'showDomainsWithNoDetections',
      name: 'Show Domains with No Detections',
      description:
        'If checked, the integration will show results for Domains that have no positive detections.',
      default: false,
      type: 'boolean',
      userCanEdit: true,
      adminOnly: false
    },
    {
      key: 'showUrlsWithNoDetections',
      name: 'Show URLs with No Detections',
      description:
        'If checked, the integration will show results for URLs that have no positive detections.',
      default: false,
      type: 'boolean',
      userCanEdit: true,
      adminOnly: false
    },
    {
      key: 'warnOnLookupLimit',
      name: 'API Key Lookup Limit Reached Warning Message',
      description:
        'Displays a warning in the Notification Window if you have reached your VirusTotal API key lookup limit.',
      default: false,
      type: 'boolean',
      userCanEdit: true,
      adminOnly: false
    },
    {
      key: 'lookupThrottleDuration',
      name: 'Lookup Throttle Duration',
      description:
        'The amount of time in minutes the integration will throttle your VirusTotal lookups in the event that you hit your lookup limit.  Once throttling has started no lookups for your configured API key will be made until the throttle time has passed.  Defaults to 1 minute.',
      default: 1,
      type: 'number',
      userCanEdit: true,
      adminOnly: false
    },
    {
      key: 'warnOnThrottle',
      name: 'Lookup Throttle Warning Message',
      description:
        'If checked, the integration will display a warning message in the overlay window when your VirusTotal lookups are being throttled. Only one message will be shown per throttle duration.',
      default: true,
      type: 'boolean',
      userCanEdit: true,
      adminOnly: false
    },
    {
      key: 'isPrivateApi',
      name: 'Is Private API',
      description:
        'If true, the integration will treat your key as a paid private API key which allows for more efficient hash lookups',
      default: false,
      type: 'boolean',
      userCanEdit: true,
      adminOnly: false
    }
  ]
};
