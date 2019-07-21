'use strict';

const request = require('request');
const { getRequestOptions } = require('./request-options.js');
const _ = require('lodash');
const config = require('./config/config');
const async = require('async');
const PendingLookupCache = require('./lib/pending-lookup-cache');
const fs = require('fs');

let Logger;
let pendingLookupCache;

let doLookupLogging;
let lookupHashSet;
let lookupIpSet;

let requestWithDefaults;

const debugLookupStats = {
  hourCount: 0,
  dayCount: 0,
  hashCount: 0,
  ipCount: 0,
  ipLookups: 0,
  hashLookups: 0
};

const throttleCache = new Map();

const BUG_ICON = `<svg aria-hidden="true" focusable="false" data-prefix="fas" data-icon="bug" role="img" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512" class="svg-inline--fa fa-bug fa-w-16"><path fill="currentColor" d="M511.988 288.9c-.478 17.43-15.217 31.1-32.653 31.1H424v16c0 21.864-4.882 42.584-13.6 61.145l60.228 60.228c12.496 12.497 12.496 32.758 0 45.255-12.498 12.497-32.759 12.496-45.256 0l-54.736-54.736C345.886 467.965 314.351 480 280 480V236c0-6.627-5.373-12-12-12h-24c-6.627 0-12 5.373-12 12v244c-34.351 0-65.886-12.035-90.636-32.108l-54.736 54.736c-12.498 12.497-32.759 12.496-45.256 0-12.496-12.497-12.496-32.758 0-45.255l60.228-60.228C92.882 378.584 88 357.864 88 336v-16H32.666C15.23 320 .491 306.33.013 288.9-.484 270.816 14.028 256 32 256h56v-58.745l-46.628-46.628c-12.496-12.497-12.496-32.758 0-45.255 12.498-12.497 32.758-12.497 45.256 0L141.255 160h229.489l54.627-54.627c12.498-12.497 32.758-12.497 45.256 0 12.496 12.497 12.496 32.758 0 45.255L424 197.255V256h56c17.972 0 32.484 14.816 31.988 32.9zM257 0c-61.856 0-112 50.144-112 112h224C369 50.144 318.856 0 257 0z" class=""></path></svg>`;

const GLOBE_ICON = `<svg viewBox="0 0 496 512" xmlns="http://www.w3.org/2000/svg" role="img" aria-hidden="true" data-icon="globe" data-prefix="fas" id="ember882" class="svg-inline--fa fa-globe fa-w-16 fa-fw  undefined ember-view"><path fill="currentColor" d="M336.5 160C322 70.7 287.8 8 248 8s-74 62.7-88.5 152h177zM152 256c0 22.2 1.2 43.5 3.3 64h185.3c2.1-20.5 3.3-41.8 3.3-64s-1.2-43.5-3.3-64H155.3c-2.1 20.5-3.3 41.8-3.3 64zm324.7-96c-28.6-67.9-86.5-120.4-158-141.6 24.4 33.8 41.2 84.7 50 141.6h108zM177.2 18.4C105.8 39.6 47.8 92.1 19.3 160h108c8.7-56.9 25.5-107.8 49.9-141.6zM487.4 192H372.7c2.1 21 3.3 42.5 3.3 64s-1.2 43-3.3 64h114.6c5.5-20.5 8.6-41.8 8.6-64s-3.1-43.5-8.5-64zM120 256c0-21.5 1.2-43 3.3-64H8.6C3.2 212.5 0 233.8 0 256s3.2 43.5 8.6 64h114.6c-2-21-3.2-42.5-3.2-64zm39.5 96c14.5 89.3 48.7 152 88.5 152s74-62.7 88.5-152h-177zm159.3 141.6c71.4-21.2 129.4-73.7 158-141.6h-108c-8.8 56.9-25.6 107.8-50 141.6zM19.3 352c28.6 67.9 86.5 120.4 158 141.6-24.4-33.8-41.2-84.7-50-141.6h-108z"></path></svg>`;

const IGNORED_IPS = new Set(['127.0.0.1', '255.255.255.255', '0.0.0.0']);

const HASH_LOOKUP_URI = 'https://www.virustotal.com/vtapi/v2/file/report';
const IP_LOOKUP_URI = 'https://www.virustotal.com/vtapi/v2/ip-address/report';

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
    if (options.warnOnThrottle && throttleCache.get(options.apiKey) === false) {
      throttleCache.set(options.apiKey, true);
      return cb(`Throttling lookups for ${options.lookupThrottleDuration} minute`, []);
    } else {
      return cb(null, []);
    }
  }

  let ipv4Entities = new Array();
  let entityLookup = {};
  let hashGroups = [];
  let hashGroup = [];

  Logger.trace(entities);
  const MAX_HASHES_PER_GROUP = options.isPrivateApi === true ? 25 : 4;

  entities.forEach(function(entity) {
    if (pendingLookupCache.isRunning(entity.value)) {
      pendingLookupCache.addPendingLookup(entity.value, cb);
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

        if (doLookupLogging === true) {
          lookupHashSet.add(entity.value);
        }
      }
    } else if (entity.isIPv4 && !entity.isPrivateIP && !IGNORED_IPS.has(entity.value)) {
      if (doLookupLogging === true) {
        lookupIpSet.add(entity.value);
      }

      pendingLookupCache.addRunningLookup(entity.value);

      ipv4Entities.push(entity);
    }
  });

  // grab any "trailing" hashes
  if (hashGroup.length > 0) {
    hashGroups.push(hashGroup);
  }

  async.parallel(
    {
      ipLookups: function(callback) {
        if (ipv4Entities.length > 0) {
          async.concat(
            ipv4Entities,
            function(ipEntity, concatDone) {
              Logger.debug({ ip: ipEntity.value }, 'Looking up IP');
              _lookupIp(ipEntity, options, concatDone);
            },
            function(err, results) {
              if (err) {
                callback(err);
                return;
              }
              callback(null, results);
            }
          );
        } else {
          callback(null, []);
        }
      },
      hashLookups: function(callback) {
        if (hashGroups.length > 0) {
          Logger.debug({ hashGroups: hashGroups }, 'Looking up HashGroups');
          async.map(
            hashGroups,
            function(hashGroup, mapDone) {
              _lookupHash(hashGroup, entityLookup, options, mapDone);
            },
            function(err, results) {
              if (err) {
                callback(err);
                return;
              }

              Logger.trace({ hashLookupResults: results }, 'HashLookup Results');

              //results is an array of hashGroup results (i.e., an array of arrays)
              let unrolledResults = [];
              results.forEach(function(hashGroup) {
                hashGroup.forEach(function(hashResult) {
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
    function(err, lookupResults) {
      if (err) {
        pendingLookupCache.reset();
        cb(err);
        return;
      }

      let combinedResults = new Array();
      lookupResults.hashLookups.forEach(function(lookupResult) {
        pendingLookupCache.removeRunningLookup(lookupResult.entity.value);
        pendingLookupCache.executePendingLookups(lookupResult);
        combinedResults.push(lookupResult);
      });

      lookupResults.ipLookups.forEach(function(lookupResult) {
        pendingLookupCache.removeRunningLookup(lookupResult.entity.value);
        pendingLookupCache.executePendingLookups(lookupResult);
        combinedResults.push(lookupResult);
      });

      pendingLookupCache.logStats();

      cb(null, combinedResults);
    }
  );
}

function _removeFromThrottleCache(apiKey) {
  return function() {
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
      setTimeout(_removeFromThrottleCache(options.apiKey), options.lookupThrottleDuration * 60 * 1000);
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
  if (doLookupLogging === true) {
    debugLookupStats.hashLookups++;
  }

  let requestOptions = {
    uri: HASH_LOOKUP_URI,
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-encoded'
    },
    form: {
      apikey: options.apiKey,
      resource: hashesArray.join(', ')
    }
  };

  let transformedRequestOptions = getRequestOptions(requestOptions, options);
  Logger.debug({ transformedRequestOptions: transformedRequestOptions }, 'Request Options for Hash Lookup');
  requestWithDefaults(transformedRequestOptions, function(err, response, body) {
    _handleRequestError(err, response, body, options, function(err, body) {
      if (err) {
        Logger.error({ err: err }, 'Error Looking up Hash');
        done(err);
        return;
      }

      let hashLookupResults = [];
      let tmpResult;

      if (_.isArray(body)) {
        body.forEach((item) => {
          tmpResult = _processHashLookupItem(item, entityLookup, options.showHashesWithNoDetections);
          if (tmpResult !== null) {
            hashLookupResults.push(tmpResult);
          }
        });
      } else {
        tmpResult = _processHashLookupItem(body, entityLookup, options.showHashesWithNoDetections);
        if (tmpResult !== null) {
          hashLookupResults.push(tmpResult);
        }
      }

      done(null, hashLookupResults);
    });
  });
}

function _processHashLookupItem(virusTotalResultItem, entityLookupHash, showHashesWithNoDetections) {
  let entity = entityLookupHash[virusTotalResultItem.resource.toLowerCase()];

  Logger.debug(
    {
      entityValue: entity.value,
      positives: virusTotalResultItem.positives,
      total: virusTotalResultItem.total,
      responseCode: virusTotalResultItem.response_code
    },
    'Result Item'
  );

  if (_isHashLookupResultHit(virusTotalResultItem, showHashesWithNoDetections)) {
    virusTotalResultItem.type = 'file';
    Logger.debug({ hash: entity.value }, 'Lookup Had Result (Caching Hit)');

    return {
      entity: entity,
      data: {
        summary: [_getSummaryTags(virusTotalResultItem)],
        details: virusTotalResultItem
      }
    };
  } else if (_isHashLookupMiss(virusTotalResultItem)) {
    Logger.debug({ hash: entity.value }, 'No Result (Caching Miss)');
    return {
      entity: entity,
      data: null
    };
  }

  Logger.debug('Ignoring result due to no positive detections');
  return null;
}

function _getSummaryTags(virusTotalResultItem) {
  return `${virusTotalResultItem.positives} ${BUG_ICON}/ ${virusTotalResultItem.total}`;
}

function _isHashLookupMiss(virusTotalResultItem) {
  if (
    virusTotalResultItem.response_code === 0 ||
    (virusTotalResultItem.positives === 0 && virusTotalResultItem.total === 0)
  ) {
    return true;
  }

  return false;
}

/**
 * For there to be a hit the response_code must be 1.  In addition, if the total number of positive
 * detections is 0 then no hit will be returned unless `showHashWithNoDetections` is set to true.
 *
 * @param virusTotalResultItem
 * @param showHashesWithNoDetections
 * @returns {boolean}
 * @private
 */
function _isHashLookupResultHit(virusTotalResultItem, showHashesWithNoDetections) {
  if (virusTotalResultItem.response_code === 1) {
    if (virusTotalResultItem.positives === 0 && showHashesWithNoDetections === false) {
      return false;
    }

    return true;
  }

  return false;
}

function _lookupIp(ipEntity, options, done) {
  //do the lookup
  if (doLookupLogging === true) {
    debugLookupStats.ipLookups++;
  }

  let requestOptions = {
    uri: IP_LOOKUP_URI,
    method: 'GET',
    qs: {
      apikey: options.apiKey,
      ip: ipEntity.value
    }
  };
  let transformedRequestOptions = getRequestOptions(requestOptions, options);
  Logger.debug({ transformedRequestOptions: transformedRequestOptions }, 'Request Options for IP Lookup');
  requestWithDefaults(transformedRequestOptions, function(err, response, body) {
    _handleRequestError(err, response, body, options, function(err, result) {
      if (err) {
        Logger.error({ err: err }, 'Error Looking up IP');
        done(err);
        return;
      }
      let ipLookupResults = [];
      ipLookupResults = _processIpLookupItem(result, ipEntity, ipLookupResults, options.showIpsWithNoDetections);
      done(null, ipLookupResults);
    });
  });
}

function _processIpLookupItem(virusTotalResultItem, ipEntity, ipLookupResults, showIpsWithNoDetections) {
  /**
   * asn (string)
   * response_code (integer)
   * as_owner (string)
   * verbose_msg (string)
   * country
   * undetected_referrer_samples (array)
   *      .positives
   *      .total
   *      .sha256
   * detected_downloaded_samples
   *      .date
   *      .positives
   *      .total
   *      .sha256
   *  detected_referrer_samples (array)
   *      .positives
   *      .total
   *      .sha256
   *  detected_urls
   *      .url
   *      .positives
   *      .total
   *      .scan_date
   *  undetected_downloaded_samples
   *      .date
   *      .positives
   *      .total
   *      .sha256
   *  resolutions
   *      .last_resolved
   *      .hostname
   */
  if (virusTotalResultItem.response_code === 1) {
    // Compute the details
    let details = _computeIpDetails(virusTotalResultItem);

    if (details.overallPositives === 0 && showIpsWithNoDetections === false) {
      // don't show any results if there are no positive detections and the user has not set showIpsWithNoDetections to true
      // We cache as a miss eventhough
      ipLookupResults.push({
        entity: ipEntity,
        data: null
      });
      return ipLookupResults;
    }

    if (details.numResolutions === 0 && details.overallPositives === 0 && details.overallTotal === 0) {
      Logger.debug({ ip: ipEntity.value }, 'No Positive Detections or Resolutions');
      // This was an empty result so we just push a null data value
      ipLookupResults.push({
        entity: ipEntity,
        data: null
      });
    } else {
      Logger.debug({ ip: ipEntity.value }, 'Had Result');
      ipLookupResults.push({
        entity: ipEntity,
        data: {
          summary: [
            `${GLOBE_ICON} ${details.numResolutions}`,
            `${details.overallPositives} ${BUG_ICON}/ ${details.overallTotal}`
          ],
          details: details
        }
      });
    }
  } else if (virusTotalResultItem.response_code === 0) {
    Logger.debug({ ip: ipEntity.value }, 'No Result');
    // This was an empty result so we just push a null data value
    ipLookupResults.push({
      entity: ipEntity,
      data: null
    });
  }

  return ipLookupResults;
}

function _computeIpDetails(result) {
  // Initialize our computed values that we want to pass through to the notification window
  let computedResults = {
    type: 'ip',
    overallPositives: 0,
    overallTotal: 0,
    overallPercent: 0,
    detectedUrlsPositive: 0,
    detectedUrlsTotal: 0,
    detectedCommunicatingSamplesPositive: 0,
    detectedCommunicatingSamplesTotal: 0,
    detectedDownloadedSamplesPositive: 0,
    detectedDownloadedSamplesTotal: 0,
    detectedReferrerSamplesPositive: 0,
    detectedReferrerSamplesTotal: 0,
    numResolutions: Array.isArray(result.resolutions) ? result.resolutions.length : 0,
    detectedUrls: result.detected_urls,
    resolutions: result.resolutions
  };

  let keys = ['detectedUrls', 'detectedCommunicatingSamples', 'detectedDownloadedSamples', 'detectedReferrerSamples'];

  let keyMappings = {
    detectedUrls: 'detected_urls',
    detectedCommunicatingSamples: 'detected_communicating_samples',
    detectedDownloadedSamples: 'detected_downloaded_samples',
    detectedReferrerSamples: 'detected_referrer_samples'
  };

  keys.forEach(function(key) {
    if (Array.isArray(result[keyMappings[key]])) {
      result[keyMappings[key]].forEach(function(row) {
        computedResults.overallPositives += row.positives;
        computedResults.overallTotal += row.total;
        computedResults[key + 'Positive'] += row.positives;
        computedResults[key + 'Total'] += row.total;
      });
    } else {
      computedResults[key + 'Positive'] = 0;
      computedResults[key + 'Total'] = 0;
    }
  });

  keys.forEach(function(key) {
    let positive = computedResults[key + 'Positive'];
    let total = computedResults[key + 'Total'];

    computedResults[key + 'Percent'] = total === 0 ? 'NA' : ((positive / total) * 100).toFixed(0) + '%';
  });

  computedResults.overallPercent =
    computedResults.overallTotal === 0
      ? 'NA'
      : ((computedResults.overallPositives / computedResults.overallTotal) * 100).toFixed(0) + '%';

  return computedResults;
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

function startup(logger) {
  Logger = logger;

  if (config && config.logging && config.logging.logLookupStats === true) {
    Logger.info({ loggerLevel: Logger._level }, 'Will do Lookup Logging');
    doLookupLogging = true;
    lookupHashSet = new Set();
    lookupIpSet = new Set();
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

  if (typeof config.request.passphrase === 'string' && config.request.passphrase.length > 0) {
    defaults.passphrase = config.request.passphrase;
  }

  if (typeof config.request.ca === 'string' && config.request.ca.length > 0) {
    defaults.ca = fs.readFileSync(config.request.ca);
  }

  if (typeof config.request.proxy === 'string' && config.request.proxy.length > 0) {
    defaults.proxy = config.request.proxy;
  }

  if (typeof config.request.rejectUnauthorized === 'boolean') {
    defaults.rejectUnauthorized = config.request.rejectUnauthorized;
  }

  defaults.json = true;

  requestWithDefaults = request.defaults(defaults);
}

function _logLookupStats() {
  debugLookupStats.ipCount = lookupIpSet.size;
  debugLookupStats.hashCount = lookupHashSet.size;

  Logger.info(debugLookupStats, 'Unique Entity Stats');

  if (debugLookupStats.hourCount == 23) {
    lookupHashSet.clear();
    lookupIpSet.clear();
    debugLookupStats.hourCount = 0;
    debugLookupStats.hashCount = 0;
    debugLookupStats.ipCount = 0;
    debugLookupStats.ipLookups = 0;
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
    (typeof userOptions.apiKey.value === 'string' && userOptions.apiKey.value.length === 0)
  ) {
    errors.push({
      key: 'apiKey',
      message: 'You must provide a VirusTotal API key'
    });
  }

  cb(null, errors);
}

module.exports = {
  doLookup: doLookup,
  startup: startup,
  validateOptions: validateOptions
};
