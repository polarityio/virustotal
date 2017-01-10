'use strict';

var request = require('request');
var _ = require('lodash');
var util = require('util');
var net = require('net');
var async = require('async');
const HASH_LOOKUP_URI = "https://www.virustotal.com/vtapi/v2/file/report";
const IP_LOOKUP_URI = "https://www.virustotal.com/vtapi/v2/ip-address/report";

var doLookup = function(entities, options, cb){
    if(typeof cb !== 'function'){
        return;
    }

    if(typeof(options.apiKey) !== 'string' || options.apiKey.length === 0){
        cb("The API key is not set.");
        return;
    }


    var hashes = new Array();
    var ipv4Entities = new Array();
    var entityLookup = {};

    entities.forEach(function(entity){
        if(entity.isHash){
            hashes.push(entity.value);
            entityLookup[entity.value.toLowerCase()] = entity;
        }else if(entity.isIPv4 && !entity.isPrivateIP){
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
};

var _handleRequestError = function(err, response, body, options, cb){
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

    if (response.statusCode !== 200) {
        cb(body);
        return;
    }

    cb(null, body);
};

var _lookupHash = function(hashesArray, entityLookup, options, done){


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
};

var _processHashLookupItem = function(virusTotalResultItem, entityLookupHash, hashLookupResults){
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
};



var _lookupIp = function(ipEntity, options, done){
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
        _handleRequestError(err, response, body, options, function(err, body){
            if(err){
                done(err);
                return;
            }
            let ipLookupResults = [];
            ipLookupResults = _processIpLookupItem(body, ipEntity, ipLookupResults);
            done(null, ipLookupResults);
        });
    });
};

var _processIpLookupItem = function(virusTotalResultItem, ipEntity, ipLookupResults){
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
        ipLookupResults.push({
            entity: ipEntity,
            isVolatile: false,
            displayValue: ipEntity.value,
            data:{
                summary: [virusTotalResultItem.as_owner, virusTotalResultItem.asn, virusTotalResultItem.country],
                details: virusTotalResultItem
            }
        });
    }else if(virusTotalResultItem.response_code === 0){
        ipLookupResults.push({
            entity: ipEntity,
            isVolatile: false,
            displayValue: ipEntity.value,
            data: null
        })
    }

    return ipLookupResults;
};
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
var _createJsonErrorPayload = function (msg, pointer, httpCode, code, title, meta) {
    return {
        errors: [
            _createJsonErrorObject(msg, pointer, httpCode, code, title, meta)
        ]
    }
};

var _createJsonErrorObject = function (msg, pointer, httpCode, code, title, meta) {
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
};

var startup = function(){

};

module.exports = {
    doLookup: doLookup,
    startup: startup
};