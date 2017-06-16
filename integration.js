'use strict';

let request = require('request');
let _ = require('lodash');
let util = require('util');
let net = require('net');
let config = require('./config/config');
let async = require('async');
let PendingLookupCache = require('./lib/pending-lookup-cache');
let fs = require('fs');

let Logger;
let pendingLookupCache;

let doLookupLogging;
let lookupHashSet;
let lookupIpSet;

let requestOptionsIp = {};
let requestOptionsHash = {};

const debugLookupStats = {
    hourCount: 0,
    dayCount: 0,
    hashCount: 0,
    ipCount: 0,
    ipLookups: 0,
    hashLookups: 0
};

const IGNORED_IPS = new Set([
    '127.0.0.1',
    '255.255.255.255',
    '0.0.0.0'
]);


const HASH_LOOKUP_URI = "https://www.virustotal.com/vtapi/v2/file/report";
const IP_LOOKUP_URI = "https://www.virustotal.com/vtapi/v2/ip-address/report";

/**
 *
 * @param entities
 * @param options
 * @param cb
 */
function doLookup(entities, options, cb) {
    if (typeof cb !== 'function') {
        return;
    }

    if (typeof(options.apiKey) !== 'string' || options.apiKey.length === 0) {
        cb("The API key is not set.");
        return;
    }

    let ipv4Entities = new Array();
    let entityLookup = {};
    let hashGroups = [];
    let hashGroup = [];

    Logger.trace(entities);
    const MAX_HASHES_PER_GROUP = options.isPrivateApi === true ? 25 : 4;

    entities.forEach(function (entity) {
        if(pendingLookupCache.isRunning(entity.value)){
            pendingLookupCache.addPendingLookup(entity.value, cb);
            return;
        }

        if ((entity.isMD5 || entity.isSHA1 || entity.isSHA256) && options.lookupFiles) {
            // VT can only look up 4 or 25 hashes at a time depending on the key type
            // so we need to split up hashes into groups of 4 or 25
            if (hashGroup.length >= MAX_HASHES_PER_GROUP) {
                hashGroups.push(hashGroup);
                hashGroup = [];
            }

            hashGroup.push(entity.value);
            entityLookup[entity.value.toLowerCase()] = entity;

            pendingLookupCache.addRunningLookup(entity.value);

            if (doLookupLogging === true) {
                lookupHashSet.add(entity.value);
            }
        } else if (entity.isIPv4 && !entity.isPrivateIP && !IGNORED_IPS.has(entity.value) && options.lookupIps) {
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

    async.parallel({
        ipLookups: function (callback) {
            if (ipv4Entities.length > 0) {
                async.concat(ipv4Entities, function (ipEntity, concatDone) {
                    Logger.debug({ip:ipEntity.value}, 'Looking up IP');
                    _lookupIp(ipEntity, options, concatDone);
                }, function (err, results) {
                    if (err) {
                        callback(err);
                        return;
                    }
                    callback(null, results);
                });
            } else {
                callback(null, []);
            }
        },
        hashLookups: function (callback) {
            if (hashGroups.length > 0) {
                Logger.debug({hashGroups: hashGroups}, 'Looking up HashGroups');
                async.map(hashGroups, function (hashGroup, mapDone) {
                    _lookupHash(hashGroup, entityLookup, options, mapDone);
                }, function (err, results) {
                    Logger.trace({hashLookupResults: results}, 'HashLookup Results');

                    if (err) {
                        callback(err);
                        return;
                    }

                    //results is an array of hashGroup results (i.e., an array of arrays)
                    let unrolledResults = [];
                    results.forEach(function (hashGroup) {
                        hashGroup.forEach(function (hashResult) {
                            unrolledResults.push(hashResult);
                        });
                    });

                    callback(null, unrolledResults);
                })
            } else {
                callback(null, []);
            }
        }
    }, function (err, lookupResults) {
        if (err) {
            pendingLookupCache.reset();
            cb(err);
            return;
        }

        let combinedResults = new Array();
        lookupResults.hashLookups.forEach(function (lookupResult) {
            pendingLookupCache.removeRunningLookup(lookupResult.entity.value);
            pendingLookupCache.executePendingLookups(lookupResult);
            combinedResults.push(lookupResult);
        });

        lookupResults.ipLookups.forEach(function (lookupResult) {
            pendingLookupCache.removeRunningLookup(lookupResult.entity.value);
            pendingLookupCache.executePendingLookups(lookupResult);
            combinedResults.push(lookupResult)
        });

        pendingLookupCache.logStats();
        cb(null, combinedResults);
    });
}



function _handleRequestError(err, response, body, options, cb) {
    if (err) {
        cb(_createJsonErrorPayload("Unable to connect to VirusTotal server", null, '500', '2A', 'VirusTotal HTTP Request Failed', {
            err: err,
            response: response,
            body: body
        }));
        return;
    }

    if (response.statusCode === 204) {
        // This means the user has reached their request limit for the API key.  In this case,
        // we don't treat it as an error and just return no results.  In the future, integrations
        // might allow non-error messages to be passed back to the user such as (VT query limit reached)
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
            cb(_createJsonErrorPayload(response.statusMessage, null, response.statusCode, '2A', 'VirusTotal HTTP Request Failed', {
                response: response,
                body: body
            }));
        }
        return;
    }

    cb(null, body);
}

function _lookupHash(hashesArray, entityLookup, options, done) {
    if (doLookupLogging === true) {
        debugLookupStats.hashLookups++;
    }

    //do the lookup
    requestOptionsHash.uri = HASH_LOOKUP_URI;
    requestOptionsHash.method = 'POST';
    requestOptionsHash.headers = {
        'Content-Type': 'application/x-www-form-encoded'
    };
    requestOptionsHash.form = {
        "apikey": options.apiKey,
        "resource": hashesArray.join(', ')
    };
    requestOptionsHash.json = true;

    request(requestOptionsHash, function (err, response, body) {
        _handleRequestError(err, response, body, options, function (err, body) {
            if (err) {
                Logger.error({err: err}, 'Error Looking up Hash');
                done(err);
                return;
            }

            let hashLookupResults = [];

            if (_.isArray(body)) {
                _.each(body, function (item) {
                    hashLookupResults = _processHashLookupItem(item, entityLookup, hashLookupResults);
                });
                //send the results to the user
            } else {
                hashLookupResults = _processHashLookupItem(body, entityLookup, hashLookupResults);
            }
            done(null, hashLookupResults);
        });
    });
}

function _processHashLookupItem(virusTotalResultItem, entityLookupHash, hashLookupResults) {
    let entity = entityLookupHash[virusTotalResultItem.resource.toLowerCase()];

    if (virusTotalResultItem.response_code === 1) {
        virusTotalResultItem.type = 'file';
        Logger.debug({hash: entity.value}, 'Had Result');
        hashLookupResults.push({
            entity: entity,
            data: {
                summary: [util.format("%d <i class='fa fa-bug integration-text-bold-color'></i> / %d",
                    virusTotalResultItem.positives, virusTotalResultItem.total)],
                details: virusTotalResultItem
            }
        });
    } else if (virusTotalResultItem.response_code === 0) {
        Logger.debug({hash: entity.value}, 'No Result');
        hashLookupResults.push({
            entity: entity,
            data: null
        })
    }

    return hashLookupResults;
}

function _lookupIp(ipEntity, options, done) {
    //do the lookup
    if (doLookupLogging === true) {
        debugLookupStats.ipLookups++;
    }

    //do the lookup
    requestOptionsIp.uri = IP_LOOKUP_URI;
    requestOptionsIp.method = 'GET';
    requestOptionsIp.qs = {
        "apikey": options.apiKey,
        "ip": ipEntity.value
    };
    requestOptionsIp.json = true;

    request(requestOptionsIp, function (err, response, body) {
        _handleRequestError(err, response, body, options, function (err, result) {
            if (err) {
                Logger.error({err: err}, 'Error Looking up IP');
                done(err);
                return;
            }
            let ipLookupResults = [];
            ipLookupResults = _processIpLookupItem(result, ipEntity, ipLookupResults);
            done(null, ipLookupResults);
        });
    });
}

function _processIpLookupItem(virusTotalResultItem, ipEntity, ipLookupResults) {
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
        Logger.debug({ip: ipEntity.value}, 'Had Result');
        ipLookupResults.push({
            entity: ipEntity,
            data: {
                summary: [
                    util.format("%d <i class='bts bt-globe integration-text-bold-color'></i>", details.numResolutions),
                    util.format("%d <i class='fa fa-bug integration-text-bold-color'></i> / %d", details.overallPositives, details.overallTotal)
                ],
                details: details
            }
        });
    } else if (virusTotalResultItem.response_code === 0) {
        Logger.debug({ip: ipEntity.value}, 'No Result');
        // This was an empty result so we just push a null data value
        ipLookupResults.push({
            entity: ipEntity,
            data: null
        })
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

    let keys = ['detectedUrls', 'detectedCommunicatingSamples',
        'detectedDownloadedSamples', 'detectedReferrerSamples'];

    let keyMappings = {
        'detectedUrls': 'detected_urls',
        'detectedCommunicatingSamples': 'detected_communicating_samples',
        'detectedDownloadedSamples': 'detected_downloaded_samples',
        'detectedReferrerSamples': 'detected_referrer_samples'
    };

    keys.forEach(function (key) {
        if (Array.isArray(result[keyMappings[key]])) {
            result[keyMappings[key]].forEach(function (row) {
                computedResults.overallPositives += row.positives;
                computedResults.overallTotal += row.total;
                computedResults[key + 'Positive'] += row.positives;
                computedResults[key + 'Total'] += row.total;
            })
        } else {
            computedResults[key + 'Positive'] = 0;
            computedResults[key + 'Total'] = 0;
        }
    });

    keys.forEach(function (key) {
        let positive = computedResults[key + 'Positive'];
        let total = computedResults[key + 'Total'];

        computedResults[key + 'Percent'] = total === 0 ? 'NA' : ((positive / total) * 100).toFixed(0) + '%';
    });

    computedResults.overallPercent = computedResults.overallTotal === 0 ? 'NA' :
        ((computedResults.overallPositives / computedResults.overallTotal) * 100).toFixed(0) + '%';

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
        errors: [
            _createJsonErrorObject(msg, pointer, httpCode, code, title, meta)
        ]
    }
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
        Logger.info({loggerLevel: Logger._level}, "Will do Lookup Logging");
        doLookupLogging = true;
        lookupHashSet = new Set();
        lookupIpSet = new Set();
        // Print log every hour
        setInterval(_logLookupStats, 60 * 60 * 1000);
    } else {
        doLookupLogging = false;
        Logger.info({loggerLevel: Logger._level}, "Will not do Lookup Logging");
    }

    pendingLookupCache = new PendingLookupCache(logger);
    if(config && config.settings && config.settings.trackPendingLookups){
        pendingLookupCache.setEnabled(true);
    }

    if(typeof config.request.cert === 'string' && config.request.cert.length > 0){
        requestOptionsIp.cert = fs.readFileSync(config.request.cert);
        requestOptionsHash.cert = fs.readFileSync(config.request.cert);
    }

    if(typeof config.request.key === 'string' && config.request.key.length > 0){
        requestOptionsIp.key = fs.readFileSync(config.request.key);
        requestOptionsHash.key = fs.readFileSync(config.request.key);
    }

    if(typeof config.request.passphrase === 'string' && config.request.passphrase.length > 0){
        requestOptionsIp.passphrase = config.request.passphrase;
        requestOptionsHash.passphrase = config.request.passphrase;
    }

    if(typeof config.request.ca === 'string' && config.request.ca.length > 0){
        requestOptionsIp.ca = fs.readFileSync(config.request.ca);
        requestOptionsHash.ca = fs.readFileSync(config.request.ca);
    }

    if(typeof config.request.proxy === 'string' && config.request.proxy.length > 0){
        requestOptionsIp.proxy = config.request.proxy;
        requestOptionsHash.proxy = config.request.proxy;
    }
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
    if (typeof userOptions.apiKey.value !== 'string' ||
        (typeof userOptions.apiKey.value === 'string' && userOptions.apiKey.value.length === 0)) {
        errors.push({
            key: 'apiKey',
            message: 'You must provide a VirusTotal API key'
        })
    }

    cb(null, errors);
}

module.exports = {
    doLookup: doLookup,
    startup: startup,
    validateOptions: validateOptions
};