'use strict';
var rest = require('unirest');
var _ = require('underscore');
var config = require('./package.json');
var util = require('util');
var net = require('net');

var url = "https://www.virustotal.com/vtapi/v2/file/report";
var hashReg = /^[a-f0-9]+$/;

var doLookup = function(entities, options, cb){
    if(typeof cb !== 'function'){
        return;
    }

    var results = new Array();
    var hashes = new Array();
    entities.forEach(function(entity){
        if(entity.isHash){
            hashes.push(entity.value);
        }
    });

    if(hashes.length > 0){

        if(typeof(options.apikey) !== 'string' || options.apikey.length === 0){
            cb("The API key is not set.");
            return;
        }

        //do the lookup
        rest.post(url).send({
            "apikey": options.apikey,
            "resource": hashes.join(', ')
        }).end(function(response){
            if(_.isArray(response.body)){
                _.each(response.body, function(item){
                    if(item.response_code === 1){
                        results.push({
                            entity: item.resource,
                            result:{
                                entity_name: item.resource,
                                tags: [util.format("%d <i class='fa fa-bug'></i> / %d", item.positives, item.total)],
                                details: item
                            }
                        });
                    }
                });
                //send the results to the user
                cb(null, results.length, results);
            }

        })
    }
};

var startup = function(){
};


module.exports = {
    doLookup: doLookup,
    startup: startup
};