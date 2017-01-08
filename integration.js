'use strict';

var request = require('request');
var _ = require('lodash');
var util = require('util');
var net = require('net');
var url = "https://www.virustotal.com/vtapi/v2/file/report";

var doLookup = function(entities, options, cb){
    if(typeof cb !== 'function'){
        return;
    }

    var results = new Array();
    var hashes = new Array();
    var entityLookup = {};

    entities.forEach(function(entity){
        if(entity.isHash){
            hashes.push(entity.value);
            entityLookup[entity.value.toLowerCase()] = entity;
        }
    });

    if(hashes.length > 0){
        if(typeof(options.apikey) !== 'string' || options.apikey.length === 0){
            cb("The API key is not set.");
            return;
        }

        //do the lookup
        request({
            uri: url,
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-encoded'
            },
            form: {
                "apikey": options.apikey,
                "resource": hashes.join(', ')
            },
            json: true
        }, function (err, response, body) {
            if(err){
                cb(_createJsonErrorPayload("Unable to connect to VirusTotal server", null, '500', '2A', 'VirusTotal HTTP Request Failed', {
                    err: err
                }));
                return;
            }

            if (response.statusCode !== 200) {
                cb(body);
                return;
            }
            // console.info("VIRUSTOTAL SERVER SIDE INTEGRATION RESPONSE:");
            // console.info(response.body);
            if(_.isArray(response.body)){
                _.each(response.body, function(item){
                    results = _processLookupItem(item, entityLookup, results);
                });
                //send the results to the user
            }else{
                results = _processLookupItem(response.body, entityLookup, results);
            }

            cb(null, results);
            return;
        })
    }else{
        cb(null, results);
    }
};

var _processLookupItem = function(virusTotalResultItem, entityLookupHash, results){
    let entity = entityLookupHash[virusTotalResultItem.resource.toLowerCase()];
    if(virusTotalResultItem.response_code === 1){
        results.push({
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
        results.push({
            entity: entity,
            isVolatile: false,
            displayValue: entity.value,
            data: null
        })
    }

    return results;
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