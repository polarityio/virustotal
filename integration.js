'use strict';

const request = require('request');
const _ = require('lodash');
const fp = require('lodash/fp');
const map = require('lodash/fp/map').convert({ cap: false });
const config = require('./config/config');
const async = require('async');
const PendingLookupCache = require('./lib/pending-lookup-cache');
const fs = require('fs');

let Logger;
let pendingLookupCache;
let domainUrlBlocklistRegex = null;
let ipBlocklistRegex = null;

let doLookupLogging;
let lookupHashSet;
let lookupIpSet;
let lookupDomainSet;
let lookupUrlSet;

let requestWithDefaults;

const debugLookupStats = {
  hourCount: 0,
  dayCount: 0,
  hashCount: 0,
  ipCount: 0,
  ipLookups: 0,
  domainCount: 0,
  domainLookups: 0,
  urlCount: 0,
  urlLookups: 0,
  hashLookups: 0
};

const throttleCache = new Map();

const BUG_ICON = `<svg aria-hidden="true" focusable="false" data-prefix="fas" data-icon="bug" role="img" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512" class="svg-inline--fa fa-bug fa-w-16"><path fill="currentColor" d="M511.988 288.9c-.478 17.43-15.217 31.1-32.653 31.1H424v16c0 21.864-4.882 42.584-13.6 61.145l60.228 60.228c12.496 12.497 12.496 32.758 0 45.255-12.498 12.497-32.759 12.496-45.256 0l-54.736-54.736C345.886 467.965 314.351 480 280 480V236c0-6.627-5.373-12-12-12h-24c-6.627 0-12 5.373-12 12v244c-34.351 0-65.886-12.035-90.636-32.108l-54.736 54.736c-12.498 12.497-32.759 12.496-45.256 0-12.496-12.497-12.496-32.758 0-45.255l60.228-60.228C92.882 378.584 88 357.864 88 336v-16H32.666C15.23 320 .491 306.33.013 288.9-.484 270.816 14.028 256 32 256h56v-58.745l-46.628-46.628c-12.496-12.497-12.496-32.758 0-45.255 12.498-12.497 32.758-12.497 45.256 0L141.255 160h229.489l54.627-54.627c12.498-12.497 32.758-12.497 45.256 0 12.496 12.497 12.496 32.758 0 45.255L424 197.255V256h56c17.972 0 32.484 14.816 31.988 32.9zM257 0c-61.856 0-112 50.144-112 112h224C369 50.144 318.856 0 257 0z" class=""></path></svg>`;
const IGNORED_IPS = new Set(['127.0.0.1', '255.255.255.255', '0.0.0.0']);

const LOOKUP_URI_BY_TYPE = {
  ip: 'https://www.virustotal.com/api/v3/ip_addresses',
  domain: 'https://www.virustotal.com/api/v3/domains',
  hash: 'https://www.virustotal.com/api/v3/files',
  url: 'https://www.virustotal.com/api/v3/urls'
};

const TYPES_BY_SHOW_NO_DETECTIONS = {
  ip: 'showIpsWithNoDetections',
  domain: 'showDomainsWithNoDetections',
  hash: 'showHashesWithNoDetections',
  url: 'showUrlsWithNoDetections'
};

/**
 *
 * @param entities
 * @param options
 * @param cb
 */
function doLookup(entities, options, cb) {
  if (throttleCache.has(options.apiKey)) {
    // the throttleCache stores whether or not we've shown the throttle warning message for this throttle duration
    // We only want to show the message once per throttleDuration (defaults to 1 minute).
    if (options.warnOnThrottle && !throttleCache.get(options.apiKey)) {
      throttleCache.set(options.apiKey, true);
      return cb(`Throttling lookups for ${options.lookupThrottleDuration} minute`, []);
    } else {
      return cb(null, []);
    }
  }

  let ipv4Entities = new Array();
  let domainEntities = new Array();
  let urlEntities = new Array();
  let entityLookup = {};
  let hashGroups = [];
  let hashGroup = [];

  Logger.trace(entities);
  const MAX_HASHES_PER_GROUP = options.maxHashesPerGroup;

  entities.forEach(function (entity) {
    if (pendingLookupCache.isRunning(entity.value))
      return pendingLookupCache.addPendingLookup(entity.value, cb);

    if (_isEntityBlocked(entity, options)) {
      return;
    }

    if (entity.isMD5 || entity.isSHA1 || entity.isSHA256) {
      // VT can only look up 4 or 25 hashes at a time depending on the key type
      // so we need to split up hashes into groups of 4 or 25
      if (hashGroup.length >= MAX_HASHES_PER_GROUP) {
        hashGroups.push(hashGroup);
        hashGroup = [];
      }

      if (!entityLookup[entity.value.toLowerCase()]) {
        // entity isn't already added
        hashGroup.push(entity.value);
        entityLookup[entity.value.toLowerCase()] = entity;
        pendingLookupCache.addRunningLookup(entity.value);

        if (doLookupLogging) lookupHashSet.add(entity.value);
      }
    } else if (entity.isIPv4 && !entity.isPrivateIP && !IGNORED_IPS.has(entity.value)) {
      if (doLookupLogging) lookupIpSet.add(entity.value);

      pendingLookupCache.addRunningLookup(entity.value);

      ipv4Entities.push(entity);
    } else if (entity.isDomain) {
      if (doLookupLogging) lookupDomainSet.add(entity.value);

      pendingLookupCache.addRunningLookup(entity.value);

      domainEntities.push(entity);
    } else if (entity.isURL) {
      if (doLookupLogging) lookupUrlSet.add(entity.value);

      pendingLookupCache.addRunningLookup(entity.value);

      urlEntities.push(entity);
    }
  });

  // grab any "trailing" hashes
  if (hashGroup.length > 0) {
    hashGroups.push(hashGroup);
  }

  async.parallel(
    {
      ipLookups: function (callback) {
        if (ipv4Entities.length > 0) {
          async.concat(
            ipv4Entities,
            function (ipEntity, concatDone) {
              Logger.debug({ ip: ipEntity.value }, 'Looking up IP');
              _lookupEntityType('ip', ipEntity, options, concatDone);
            },
            function (err, results) {
              if (err) return callback(err);

              callback(null, results);
            }
          );
        } else {
          callback(null, []);
        }
      },
      domainLookups: function (callback) {
        if (domainEntities.length > 0) {
          async.concat(
            domainEntities,
            function (domainEntity, concatDone) {
              Logger.debug({ domain: domainEntity.value }, 'Looking up Domain');
              _lookupEntityType('domain', domainEntity, options, concatDone);
            },
            function (err, results) {
              if (err) return callback(err);

              callback(null, results);
            }
          );
        } else {
          callback(null, []);
        }
      },
      urlLookups: function (callback) {
        if (urlEntities.length > 0) {
          async.concat(
            urlEntities,
            function (urlEntity, concatDone) {
              Logger.debug({ url: urlEntity.value }, 'Looking up URL');
              _lookupUrl(urlEntity, options, concatDone);
            },
            function (err, results) {
              if (err) return callback(err);

              callback(null, results);
            }
          );
        } else {
          callback(null, []);
        }
      },
      hashLookups: function (callback) {
        if (hashGroups.length > 0) {
          Logger.debug({ hashGroups: hashGroups }, 'Looking up HashGroups');
          async.map(
            hashGroups,
            function (hashGroup, mapDone) {
              _lookupHash(hashGroup, entityLookup, options, mapDone);
            },
            function (err, results) {
              if (err) return callback(err);

              Logger.trace({ hashLookupResults: results }, 'HashLookup Results');

              //results is an array of hashGroup results (i.e., an array of arrays)
              let unrolledResults = [];
              results.forEach(function (hashGroup) {
                hashGroup.forEach(function (hashResult) {
                  unrolledResults.push(hashResult);
                });
              });

              callback(null, unrolledResults);
            }
          );
        } else {
          callback(null, []);
        }
      }
    },
    function (err, lookupResults) {
      if (err) {
        pendingLookupCache.reset();
        return cb(err);
      }

      let combinedResults = new Array();

      ['hashLookups', 'ipLookups', 'domainLookups', 'urlLookups'].forEach((key) =>
        lookupResults[key].forEach(function (lookupResult) {
          pendingLookupCache.removeRunningLookup(fp.get('entity.value', lookupResult));
          pendingLookupCache.executePendingLookups(lookupResult);
          combinedResults.push(lookupResult);
        })
      );

      pendingLookupCache.logStats();

      cb(null, combinedResults);
    }
  );
}

function _isEntityBlocked(entity, options) {
  const blocklist = options.blocklist;
  const currentIpBlocklistRegex = options.ipBlocklistRegex;
  const currentDomainUrlBlocklistRegex = options.domainUrlBlocklistRegex;

  // initialize regex if needed
  if (ipBlocklistRegex === null && currentIpBlocklistRegex.length > 0) {
    Logger.debug('Initializing ip blocklist regex');
    ipBlocklistRegex = new RegExp(currentIpBlocklistRegex);
  }

  if (domainUrlBlocklistRegex === null && currentDomainUrlBlocklistRegex.length > 0) {
    Logger.debug('Initializing domain/url blocklist regex');
    domainUrlBlocklistRegex = new RegExp(currentDomainUrlBlocklistRegex);
  }

  if (currentIpBlocklistRegex.length === 0) {
    ipBlocklistRegex = null;
  }

  if (currentDomainUrlBlocklistRegex.length === 0) {
    domainUrlBlocklistRegex = null;
  }

  if (
    ipBlocklistRegex !== null &&
    ipBlocklistRegex.toString() !== `/${currentIpBlocklistRegex}/`
  ) {
    Logger.debug('Updating ipBlocklistRegex');
    ipBlocklistRegex = new RegExp(currentIpBlocklistRegex);
  }

  if (
    domainUrlBlocklistRegex !== null &&
    domainUrlBlocklistRegex.toString() !== `/${currentDomainUrlBlocklistRegex}/`
  ) {
    Logger.debug('Updating domainUrlBlocklistRegex');
    domainUrlBlocklistRegex = new RegExp(currentDomainUrlBlocklistRegex);
  }

  Logger.trace({ blocklist }, 'Blocklist value');

  if (_.includes(blocklist, entity.value.toLowerCase())) {
    Logger.debug({ entity: entity.value }, 'Blocked Entity');
    return true;
  }

  if (entity.isIP && !entity.isPrivateIP) {
    if (ipBlocklistRegex !== null) {
      if (ipBlocklistRegex.test(entity.value)) {
        Logger.debug({ ip: entity.value }, 'IP lookup blocked due to blocklist regex');
        return true;
      }
    }
  }

  if (entity.isDomain) {
    if (domainUrlBlocklistRegex !== null) {
      if (domainUrlBlocklistRegex.test(entity.value)) {
        Logger.debug(
          { domain: entity.value },
          'Domain lookup blocked due to blocklist regex'
        );
        return true;
      }
    }
  }

  if (entity.isURL) {
    if (domainUrlBlocklistRegex !== null) {
      const urlObj = new URL(entity.value);
      const hostname = urlObj.hostname;
      Logger.debug(hostname, 'Hostname of url to block');
      if (domainUrlBlocklistRegex.test(hostname)) {
        Logger.debug({ url: entity.value }, 'URL lookup blocked due to blocklist regex');
        return true;
      }
    }
  }

  return false;
}

function _removeFromThrottleCache(apiKey) {
  return function () {
    throttleCache.delete(apiKey);
  };
}

function _handleRequestError(err, response, body, options, cb) {
  if (err) {
    cb(
      _createJsonErrorPayload(
        'Unable to connect to VirusTotal server',
        null,
        '500',
        '2A',
        'VirusTotal HTTP Request Failed',
        {
          err: err,
          response: response,
          body: body
        }
      )
    );
    return;
  }

  if (response.statusCode === 204) {
    // This means the user has reached their request limit for the API key.  In this case,
    // we don't treat it as an error and just return no results.  In the future, integrations
    // might allow non-error messages to be passed back to the user such as (VT query limit reached)
    if (!throttleCache.has(options.apiKey)) {
      setTimeout(
        _removeFromThrottleCache(options.apiKey),
        options.lookupThrottleDuration * 60 * 1000
      );
      // false here indicates that the throttle warning message has not been shown to the user yet
      throttleCache.set(options.apiKey, false);
    }

    if (options.warnOnLookupLimit) {
      cb('API Lookup Limit Reached');
    } else {
      cb(null, []);
    }

    return;
  }

  if (response.statusCode === 403) {
    cb('You do not have permission to access VirusTotal.  Please check your API key');
    return;
  }

  if (response.statusCode === 404) return cb();

  if (response.statusCode !== 200) {
    if (body) {
      cb(body);
    } else {
      cb(
        _createJsonErrorPayload(
          response.statusMessage,
          null,
          response.statusCode,
          '2A',
          'VirusTotal HTTP Request Failed',
          {
            response: response,
            body: body
          }
        )
      );
    }
    return;
  }

  cb(null, body);
}

function _lookupHash(hashesArray, entityLookup, options, done) {
  if (doLookupLogging) {
    debugLookupStats.hashLookups++;
  }

  async.mapLimit(
    hashesArray,
    10,
    (hashValue, next) => {
      let requestOptions = {
        uri: `${LOOKUP_URI_BY_TYPE.hash}/${hashValue}`,
        method: 'GET',
        headers: { 'x-apikey': options.apiKey }
      };
      requestWithDefaults(requestOptions, function (err, response, body) {
        _handleRequestError(err, response, body, options, function (err, body) {
          if (err) {
            Logger.error(err, 'Error Looking up Hash');
            return next(err);
          }

          const formattedResult = _processLookupItem(
            'file',
            body,
            entityLookup[fp.toLower(hashValue)],
            options[TYPES_BY_SHOW_NO_DETECTIONS.hash],
            options.showNoInfoTag
          );

          return next(null, formattedResult);
        });
      });
    },
    (err, results) => {
      if (err) return done(err);

      done(null, fp.compact(results));
    }
  );
}

function _lookupUrl(entity, options, done) {
  if (doLookupLogging) debugLookupStats.urlLookups++;

  const urlAsBase64WithoutPadding = Buffer.from(entity.value)
    .toString('base64')
    .replace(/=+$/, '');
  let requestOptions = {
    uri: `${LOOKUP_URI_BY_TYPE.url}/${urlAsBase64WithoutPadding}`,
    method: 'GET',
    headers: { 'x-apikey': options.apiKey }
  };

  Logger.debug({ requestOptions }, 'Request Options for URL Lookup');

  requestWithDefaults(requestOptions, function (err, response, body) {
    _handleRequestError(err, response, body, options, function (err, result) {
      if (err) {
        Logger.error(err, 'Error Looking up URL');
        return done(err);
      }

      const lookupResult = _processLookupItem(
        'url',
        result,
        entity,
        options[TYPES_BY_SHOW_NO_DETECTIONS.url],
        options.showNoInfoTag
      );

      done(null, lookupResult);
    });
  });
}

const _processLookupItem = (
  type,
  result,
  entity,
  showEntitiesWithNoDetections,
  showNoInfoTag
) => {
  const data = fp.get('data', result);
  const attributes = fp.get('attributes', data);
  const lastAnalysisStats = fp.get('last_analysis_stats', attributes);
  const totalResults = fp.flow(
    fp.pick(['undetected', 'malicious', 'suspicious', 'harmless']),
    fp.values,
    fp.sum
  )(lastAnalysisStats);
  const totalMalicious = fp.get('malicious', lastAnalysisStats);

  if (
    !result ||
    !totalResults ||
    (type === 'url' && !attributes.last_http_response_code) ||
    (!totalMalicious && !showEntitiesWithNoDetections && !showNoInfoTag)
  ) {
    return {
      entity,
      data: null
    };
  }

  if (!totalMalicious && !showEntitiesWithNoDetections && showNoInfoTag) {
    return {
      entity,
      data: {
        summary: ['No Information in VirusTotal'],
        details: {
          noInfoMessage: true
        }
      }
    };
  }

  const scans = fp.flow(
    fp.get('last_analysis_results'),
    map((scanResult, scanName) => ({
      name: scanName,
      detected: scanResult.category === 'malicious',
      result:
        !scanResult.result && scanResult.category === 'type-unsupported'
          ? 'type-unsupported'
          : ['clean', 'suspicious', 'malware', 'malicious', 'unrated'].includes(
              scanResult.result
            )
          ? fp.capitalize(scanResult.result)
          : scanResult.result
    }))
  )(attributes);

  const coreLink = `https://www.virustotal.com/gui/${fp.replace('_', '-', data.type)}/${
    data.id
  }`;

  const detailsTab = getDetailFields(DETAILS_FORMATS[type], attributes);

  return {
    entity,
    data: {
      summary: [
        `${totalMalicious} ${BUG_ICON}/ ${totalResults}`,
        ...fp.flow(
          fp.filter(fp.get('detected')),
          fp.map(fp.get('result')),
          fp.uniq,
          fp.slice(0, 3)
        )(scans),
        ...(!totalMalicious && showNoInfoTag ? ['No Information in VirusTotal'] : [])
      ],
      details: {
        type,
        detectionsLink: `${coreLink}/detection`,
        relationsLink: `${coreLink}/relations`,
        detailsLink: `${coreLink}/details`,
        total: totalResults,
        scan_date: new Date(attributes.last_modification_date * 1000),
        positives: totalMalicious,
        positiveScans: fp.flow(
          fp.filter(fp.get('detected')),
          fp.orderBy('result', 'desc')
        )(scans),
        negativeScans: fp.flow(
          fp.filter(({ detected }) => !detected),
          fp.orderBy('result', 'desc')
        )(scans),
        detailsTab,
        tags: attributes.tags
      }
    }
  };
};

const DETAILS_FORMATS = {
  file: [
    { key: 'Basic Properties', isTitle: true },
    { key: 'File type', path: 'type_description' },
    {
      key: 'File size',
      path: 'size',
      transformation: (size) => `${~~(size / 1049295 / 0.01) * 0.01} MB (${size} bytes)`
    },
    { key: 'MD5', path: 'md5' },
    { key: 'SHA-1', path: 'sha1' },
    { key: 'SHA-256', path: 'sha256' },
    { key: 'Vhash', path: 'vhash' },
    { key: 'Authentihash', path: 'authentihash' },
    { key: 'Imphash', path: 'pe_info.imphash' },
    { key: 'Rich PE header hash', path: 'pe_info.rich_pe_header_hash' },
    { key: 'SSDEEP', path: 'ssdeep' },
    { key: 'TLSH', path: 'tlsh' },
    { key: 'Magic', path: 'magic' },
    {
      key: 'TrID',
      path: 'trid',
      isList: true,
      transformation: fp.map((trid) => `${trid.file_type} (${trid.probability}%)`)
    },
    { key: 'PEiD', path: 'packers.PEiD' }
  ],
  url: [
    { key: 'Basic Properties', isTitle: true },
    { key: 'Final URL', path: 'last_final_url' },
    { key: 'Status Code', path: 'last_http_response_code' },
    {
      key: 'Body Length',
      path: 'last_http_response_content_length',
      transformation: (size) => `${size} B`
    },
    { key: 'Body SHA-256', path: 'last_http_response_content_sha256' },
    {
      key: 'Categories',
      path: 'categories',
      isObject: true
    },
    {
      key: 'Headers',
      path: 'last_http_response_headers',
      isObject: true
    }
  ],
  domain: [
    { key: 'Basic Properties', isTitle: true },
    { key: 'Registrar', path: 'registrar' },
    {
      key: 'Last DNS Records',
      path: 'last_dns_records',
      isObject: true,
      transformation: fp.reduce(
        (agg, record) => ({
          ...agg,
          [`Type - ${record.type}`]: `${record.value} (TTL ${record.ttl})`
        }),
        {}
      )
    },
    {
      key: 'Categories',
      path: 'categories',
      isObject: true
    }
  ],
  ip: [
    { key: 'Basic Properties', isTitle: true },
    { key: 'Network', path: 'network' },
    { key: 'Autonomous System Number', path: 'asn' },
    { key: 'Autonomous System Label', path: 'as_owner' },
    { key: 'Regional Internet Registry', path: 'regional_internet_registry' },
    { key: 'Country', path: 'country' },
    { key: 'Continent', path: 'continent' }
  ]
};

const getDetailFields = (detailFields, attributes) =>
  fp.map((detailField) => {
    const value = fp.get(detailField.path, attributes);
    const transformedValue = detailField.transformation
      ? detailField.transformation(value)
      : value;

    return {
      ...detailField,
      ...(value && {
        value: transformedValue
      })
    };
  }, detailFields);

function _lookupEntityType(type, entity, options, done) {
  if (doLookupLogging) debugLookupStats[`${type}Lookups`]++;

  let requestOptions = {
    uri: `${LOOKUP_URI_BY_TYPE[type]}/${entity.value}`,
    method: 'GET',
    headers: { 'x-apikey': options.apiKey }
  };

  Logger.debug({ requestOptions }, 'Request Options for Type detections Lookup');

  requestWithDefaults(requestOptions, function (err, response, body) {
    _handleRequestError(err, response, body, options, function (err, result) {
      if (err) {
        Logger.error(err, `Error Looking up ${_.startCase(type)}`);
        return done(err);
      }

      let lookupResults = _processLookupItem(
        type,
        result,
        entity,
        options[TYPES_BY_SHOW_NO_DETECTIONS[type]],
        options.showNoInfoTag
      );

      if (!fp.get('data.details', lookupResults)) return done();

      done(null, lookupResults);
    });
  });
}

/**
 * Helper method that creates a fully formed JSON payload for a single error
 * @param msg
 * @param pointer
 * @param httpCode
 * @param code
 * @param title
 * @returns {{errors: *[]}}
 * @private
 */
function _createJsonErrorPayload(msg, pointer, httpCode, code, title, meta) {
  return {
    errors: [_createJsonErrorObject(msg, pointer, httpCode, code, title, meta)]
  };
}

function _createJsonErrorObject(msg, pointer, httpCode, code, title, meta) {
  let error = {
    detail: msg,
    status: httpCode.toString(),
    title: title,
    code: 'VIRUSTOTAL_' + code.toString()
  };

  if (pointer) {
    error.source = {
      pointer: pointer
    };
  }

  if (meta) {
    error.meta = meta;
  }

  return error;
}

function onDetails(lookupObject, options, cb) {
  const entity = fp.get('entity', lookupObject);
  if (fp.get('entity.isIP', lookupObject) || fp.get('entity.isDomain', lookupObject)) {
    const type = fp.get('entity.isIP', lookupObject) ? 'ip' : 'domain';

    let relationsRefFilesRequestOptions = {
      uri: `${LOOKUP_URI_BY_TYPE[type]}/${entity.value}/referrer_files`,
      method: 'GET',
      headers: { 'x-apikey': options.apiKey }
    };

    Logger.debug(
      { relationsRefFilesRequestOptions },
      'Request Options for Type referrer_files Relations Lookup'
    );

    requestWithDefaults(relationsRefFilesRequestOptions, function (err, response, body) {
      _handleRequestError(err, response, body, options, function (err, refFilesResult) {
        if (err) {
          Logger.error(err, `Error Looking up ${_.startCase(type)}`);
          return done(err);
        }

        if (refFilesResult.data) {
          const referenceFiles = fp.flow(
            fp.getOr([], 'data'),
            fp.map((referenceFile) => ({
              link:
                referenceFile.attributes &&
                `https://www.virustotal.com/gui/${referenceFile.type}/${referenceFile.id}/detection`,
              name: fp.getOr(
                referenceFile.id,
                'attributes.meaningful_name',
                referenceFile
              ),
              type: fp.getOr(referenceFile.type, 'attributes.type_tag', referenceFile),
              detections: referenceFile.attributes
                ? `${fp.getOr(
                    0,
                    'attributes.last_analysis_stats.malicious',
                    referenceFile
                  )} / ${fp.getOr(
                    0,
                    'attributes.last_analysis_stats.undetected',
                    referenceFile
                  )}`
                : '-',
              scannedDate: fp.flow(
                fp.getOr('-', 'attributes.last_analysis_date'),
                (x) => new Date(x * 1000)
              )(referenceFile)
            }))
          )(refFilesResult);

          lookupObject.data.details = {
            ...fp.get('data.details', lookupObject),
            expandedWhoisMap: {},
            referenceFiles
          };
        }

        let relationsWhoIsRequestOptions = {
          uri: `${LOOKUP_URI_BY_TYPE[type]}/${entity.value}/historical_whois`,
          method: 'GET',
          headers: { 'x-apikey': options.apiKey }
        };

        Logger.debug(
          { relationsWhoIsRequestOptions },
          'Request Options for Type historical_whois Relations Lookup'
        );

        requestWithDefaults(relationsWhoIsRequestOptions, function (err, response, body) {
          _handleRequestError(err, response, body, options, function (err, whoIsResult) {
            if (err) {
              Logger.error(err, `Error Looking up ${_.startCase(type)}`);
              return done(err);
            }

            if (whoIsResult.data) {
              const historicalWhoIs = fp.flow(
                fp.getOr([], 'data'),
                fp.map((whoIsLookup) => ({
                  last_updated: fp.flow(
                    fp.get('attributes.last_updated'),
                    (x) => new Date(x * 1000)
                  )(whoIsLookup),
                  ...fp.get('attributes.whois_map', whoIsLookup)
                }))
              )(whoIsResult);

              lookupObject.data.details = {
                ...fp.get('data.details', lookupObject),
                expandedWhoisMap: {},
                historicalWhoIs
              };
            }

            Logger.trace({ lookupObject }, 'lookupObject');
            cb(null, lookupObject.data);
          });
        });
      });
    });
  } else {
    return cb(null, lookupObject.data);
  }
}

function startup(logger) {
  Logger = logger;

  if (config && config.logging && config.logging.logLookupStats) {
    Logger.info({ loggerLevel: Logger._level }, 'Will do Lookup Logging');
    doLookupLogging = true;
    lookupHashSet = new Set();
    lookupIpSet = new Set();
    lookupDomainSet = new Set();
    lookupUrlSet = new Set();
    // Print log every hour
    setInterval(_logLookupStats, 60 * 60 * 1000);
  } else {
    doLookupLogging = false;
    Logger.info({ loggerLevel: Logger._level }, 'Will not do Lookup Logging');
  }

  pendingLookupCache = new PendingLookupCache(logger);
  if (config && config.settings && config.settings.trackPendingLookups) {
    pendingLookupCache.setEnabled(true);
  }

  let defaults = {};

  if (typeof config.request.cert === 'string' && config.request.cert.length > 0) {
    defaults.cert = fs.readFileSync(config.request.cert);
  }

  if (typeof config.request.key === 'string' && config.request.key.length > 0) {
    defaults.key = fs.readFileSync(config.request.key);
  }

  if (
    typeof config.request.passphrase === 'string' &&
    config.request.passphrase.length > 0
  ) {
    defaults.passphrase = config.request.passphrase;
  }

  if (typeof config.request.ca === 'string' && config.request.ca.length > 0) {
    defaults.ca = fs.readFileSync(config.request.ca);
  }

  if (typeof config.request.proxy === 'string' && config.request.proxy.length > 0) {
    defaults.proxy = config.request.proxy;
  }

  // if (typeof config.request.rejectUnauthorized === 'boolean') {
  defaults.rejectUnauthorized = false;
  // }

  defaults.json = true;

  requestWithDefaults = request.defaults(defaults);
}

function _logLookupStats() {
  debugLookupStats.ipCount = lookupIpSet.size;
  debugLookupStats.domainCount = lookupDomainSet.size;
  debugLookupStats.urlCount = lookupUrlSet.size;
  debugLookupStats.hashCount = lookupHashSet.size;

  Logger.info(debugLookupStats, 'Unique Entity Stats');

  if (debugLookupStats.hourCount == 23) {
    lookupHashSet.clear();
    lookupIpSet.clear();
    lookupDomainSet.clear();
    lookupUrlSet.clear();
    debugLookupStats.hourCount = 0;
    debugLookupStats.hashCount = 0;
    debugLookupStats.ipCount = 0;
    debugLookupStats.ipLookups = 0;
    debugLookupStats.domainCount = 0;
    debugLookupStats.domainLookups = 0;
    debugLookupStats.urlCount = 0;
    debugLookupStats.urlLookups = 0;
    debugLookupStats.hashLookups = 0;
    debugLookupStats.dayCount++;
  } else {
    debugLookupStats.hourCount++;
  }
}

function validateOptions(userOptions, cb) {
  let errors = [];
  if (
    typeof userOptions.apiKey.value !== 'string' ||
    (typeof userOptions.apiKey.value === 'string' &&
      userOptions.apiKey.value.length === 0)
  ) {
    errors.push({
      key: 'apiKey',
      message: 'You must provide a VirusTotal API key'
    });
  }

  let maxHashesPerGroup = userOptions.maxHashesPerGroup.value;
  if (_.isNaN(maxHashesPerGroup) || maxHashesPerGroup <= 0) {
    errors.push({
      key: 'maxHashesPerGroup',
      message: 'Maximum number of hashes per lookup request must be greater than 0'
    });
  }

  cb(null, errors);
}

function fetchNames(entity, options, cb) {
  if (entity.isMD5 || entity.isSHA1 || entity.isSHA256) {
    request.get(
      `https://www.virustotal.com/api/v3/files/${entity.value}`,
      {
        method: 'GET',
        headers: { 'x-apikey': options.apiKey }
      },
      (err, response, body) => {
        _handleRequestError(err, response, body, options, (err, results) => {
          if (err) {
            Logger.trace({ err }, 'Error retrying lookup');
            cb(err);
          }

          return cb(null, results);
        });
      }
    );
  } else {
    return cb(null);
  }
}

function onMessage(payload, options, callback) {
  switch (payload.action) {
    case 'FETCH_NAMES':
      fetchNames(payload.entity, options, (err, lookupResults) => {
        const results = Object.assign({}, JSON.parse(lookupResults)); // JSON to POJO

        if (err) {
          Logger.trace({ err }, 'Error retrying lookup');
          callback(err);
        } else {
          callback(
            null,
            results && results && results.data === null
              ? { data: { summary: [] } }
              : results
          );
        }
      });
      break;
  }
}

module.exports = {
  doLookup,
  onDetails,
  startup,
  onMessage,
  validateOptions
};
