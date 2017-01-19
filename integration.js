'use strict';

let request = require('request');
let _ = require('lodash');
let util = require('util');
let net = require('net');
let async = require('async');
let Logger;

const HASH_LOOKUP_URI = "https://www.virustotal.com/vtapi/v2/file/report";
const IP_LOOKUP_URI = "https://www.virustotal.com/vtapi/v2/ip-address/report";

/**
 *
 * @param entities
 * @param options
 * @param cb
 */
function doLookup(entities, options, cb){
    //
    // Logger.info("LOGGING FROM VIRUSTOTAL");
    // Logger.warn("Warning from VT");
    // Logger.error("ERror from VT");
    // Logger.debug("Debug from VT");
    // Logger.trace("Trace from VT");

    if(typeof cb !== 'function'){
        return;
    }

    if(typeof(options.apiKey) !== 'string' || options.apiKey.length === 0){
        cb("The API key is not set.");
        return;
    }

    let hashes = new Array();
    let ipv4Entities = new Array();
    let entityLookup = {};

    entities.forEach(function(entity){
        if((entity.isMD5 || entity.isSHA1 || entity.isSHA256) && options.lookupFiles){
            hashes.push(entity.value);
            entityLookup[entity.value.toLowerCase()] = entity;
        }else if(entity.isIPv4 && !entity.isPrivateIP && options.lookupIps){
            ipv4Entities.push(entity);
        }
    });

    async.parallel({
        ipLookups: function(callback){
            if(ipv4Entities.length > 0){
                async.concat(ipv4Entities, function(ipEntity, concatDone){
                    _lookupIp(ipEntity, options, concatDone);
                }, function(err, results){
                    if(err){
                        callback(err);
                        return;
                    }
                    callback(null, results);
                });
            }else{
                callback(null, []);
            }
        },
        hashLookups: function(callback){
            if(hashes.length > 0){
                _lookupHash(hashes, entityLookup, options, callback);
            }else{
                callback(null, []);
            }
        }
    }, function(err, lookupResults){
        if(err){
            cb(err);
            return;
        }

        let combinedResults = new Array();
        lookupResults.hashLookups.forEach(function(lookupResult){
            combinedResults.push(lookupResult);
        });

        lookupResults.ipLookups.forEach(function(lookupResult){
            combinedResults.push(lookupResult)
        });

        cb(null, combinedResults);
    });
}

function _handleRequestError(err, response, body, options, cb){
    if(err){
        cb(_createJsonErrorPayload("Unable to connect to VirusTotal server", null, '500', '2A', 'VirusTotal HTTP Request Failed', {
            err: err
        }));
        return;
    }

    if(response.statusCode === 204){
        // This means the user has reached their request limit for the API key.  In this case,
        // we don't treat it as an error and just return no results.  In the future, integrations
        // might allow non-error messages to be passed back to the user such as (VT query limit reached)
        if(options.warnOnLookupLimit){
            cb('API Lookup Limit Reached');
        }else{
            cb(null, []);
        }

        return;
    }

    if(response.statusCode === 403){
        cb('You do not have permission to access VirusTotal.  Please check your API key');
        return;
    }

    if (response.statusCode !== 200) {
        if(body){
            cb(body);
        }else{
            cb(response.statusMessage);
        }
        return;
    }

    cb(null, body);
}

function _lookupHash(hashesArray, entityLookup, options, done){
    //do the lookup
    request({
        uri: HASH_LOOKUP_URI,
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-encoded'
        },
        form: {
            "apikey": options.apiKey,
            "resource": hashesArray.join(', ')
        },
        json: true
    }, function (err, response, body) {
        _handleRequestError(err, response, body, options, function(err, body){
            if(err){
                done(err);
                return;
            }

            let hashLookupResults = [];

            if(_.isArray(body)){
                _.each(body, function(item){
                    hashLookupResults = _processHashLookupItem(item, entityLookup, hashLookupResults);
                });
                //send the results to the user
            }else{
                hashLookupResults = _processHashLookupItem(body, entityLookup, hashLookupResults);
            }
            done(null, hashLookupResults);
        });
    });
}

function _processHashLookupItem(virusTotalResultItem, entityLookupHash, hashLookupResults){
    let entity = entityLookupHash[virusTotalResultItem.resource.toLowerCase()];

    if(virusTotalResultItem.response_code === 1){
        hashLookupResults.push({
            entity: entity,
            isVolatile: false,
            displayValue: entity.value,
            data:{
                summary: [util.format("%d <i class='fa fa-bug'></i> / %d",
                    virusTotalResultItem.positives, virusTotalResultItem.total)],
                details: virusTotalResultItem
            }
        });
    }else if(virusTotalResultItem.response_code === 0){
        hashLookupResults.push({
            entity: entity,
            isVolatile: false,
            displayValue: entity.value,
            data: null
        })
    }

    return hashLookupResults;
}

function _lookupIp(ipEntity, options, done){
    //do the lookup
    request({
        uri: IP_LOOKUP_URI,
        method: 'GET',
        qs: {
            "apikey": options.apiKey,
            "ip": ipEntity.value
        },
        json: true
    }, function (err, response, body) {
        _handleRequestError(err, response, body, options, function(err, result){
            if(err){
                done(err);
                return;
            }
            let ipLookupResults = [];
            ipLookupResults = _processIpLookupItem(result, ipEntity, ipLookupResults);
            done(null, ipLookupResults);
        });
    });
}

function _processIpLookupItem(virusTotalResultItem, ipEntity, ipLookupResults){
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
    if(virusTotalResultItem.response_code === 1){
        // Compute the details
        let details = _computeIpDetails(virusTotalResultItem);

        ipLookupResults.push({
            entity: ipEntity,
            isVolatile: false,
            displayValue: ipEntity.value,
            data:{
                summary: [
                    util.format("%d <i class='bts bt-globe integration-text-bold-color'></i>", details.numResolutions),
                    util.format("%d <i class='fa fa-bug integration-text-bold-color'></i> / %d", details.overallPositives, details.overallTotal)
                ],
                details: details
            }
        });
    }else if(virusTotalResultItem.response_code === 0){
        // This was an empty result so we just push a null data value
        ipLookupResults.push({
            entity: ipEntity,
            isVolatile: false,
            displayValue: ipEntity.value,
            data: null
        })
    }

    return ipLookupResults;
}

function _computeIpDetails(result){
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

    keys.forEach(function(key){
        if(Array.isArray(result[keyMappings[key]])) {
            result[keyMappings[key]].forEach(function (row) {
                Logger.info(row);
                computedResults.overallPositives += row.positives;
                computedResults.overallTotal += row.total;
                computedResults[key + 'Positive'] += row.positives;
                computedResults[key + 'Total'] += row.total;
            })
        }else{
            computedResults[key + 'Positive'] = 0;
            computedResults[key + 'Total'] = 0;
        }
    });

    keys.forEach(function(key){
       let positive = computedResults[key + 'Positive'];
       let total = computedResults[key + 'Total'];

       computedResults[key + 'Percent'] = total === 0 ? 'NA' : ((positive / total) * 100).toFixed(0) + '%';
    });

    computedResults.overallPercent = computedResults.overallTotal === 0 ? 'NA' :
        ((computedResults.overallPositives / computedResults.overallTotal) * 100).toFixed(0) + '%';

    //Logger.info(computedResults);

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

function startup(logger){
    Logger = logger;
}

function validateOptions(userOptions, cb) {
    let errors = [];
    if(typeof userOptions.apiKey.value !== 'string' ||
        (typeof userOptions.apiKey.value === 'string' && userOptions.apiKey.value.length === 0)){
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