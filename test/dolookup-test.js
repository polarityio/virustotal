/*
 * Copyright (c) 2017. Breach Intelligence, Inc.
 * All rights reserved
 */

'use strict';

let chai = require('chai');
let expect = chai.expect;
let nock = require('nock');
let integration = require('../integration');

describe('doLookup()', function () {
    before(function (done) {
        integration.startup({
            trace: function () {
            },
            info: function () {
            },
            debug: function (msg) {
                //console.info(msg)
            },
            error: function () {
            }
        });

        nock('https://www.virustotal.com')
            .post('/vtapi/v2/file/report', {
                "apikey": 'fakekey',
                "resource": '7e3485f5edd48ffce37b0b0b735cd97f5ab514aa8dc4d6bc16cc4c40fb3fb570'
            })
            .times(2)
            .reply(200, {
                    "scans": {
                        "Bkav": {
                            "detected": false,
                            "version": "1.3.0.9282",
                            "result": null,
                            "update": "20170727"
                        },
                        "MicroWorld-eScan": {
                            "detected": false,
                            "version": "12.0.250.0",
                            "result": null,
                            "update": "20170727"
                        },
                        "nProtect": {
                            "detected": false,
                            "version": "2017-07-27.01",
                            "result": null,
                            "update": "20170727"
                        }
                    },
                    "scan_id": "7e3485f5edd48ffce37b0b0b735cd97f5ab514aa8dc4d6bc16cc4c40fb3fb570-1501185873",
                    "sha1": "c21dc47d57437909f9cac14e786c77e9f3e78e56",
                    "resource": "7e3485f5edd48ffce37b0b0b735cd97f5ab514aa8dc4d6bc16cc4c40fb3fb570",
                    "response_code": 1,
                    "scan_date": "2017-07-27 20:04:33",
                    "permalink": "https://www.virustotal.com/file/7e3485f5edd48ffce37b0b0b735cd97f5ab514aa8dc4d6bc16cc4c40fb3fb570/analysis/1501185873/",
                    "verbose_msg": "Scan finished, information embedded",
                    "total": 62,
                    "positives": 0,
                    "sha256": "7e3485f5edd48ffce37b0b0b735cd97f5ab514aa8dc4d6bc16cc4c40fb3fb570",
                    "md5": "e87c6a38e61a712c48025a6ad54c1113"
                }
            );

        done();
    });

    it('should lookup hash', function (done) {
        integration.doLookup([{
            type: 'hash',
            types: ['hash', 'sha256'],
            value: '7e3485f5edd48ffce37b0b0b735cd97f5ab514aa8dc4d6bc16cc4c40fb3fb570',
            isSHA256: true
        }], {
            apiKey: 'fakekey',
            lookupIps: false,
            lookupFiles: true,
            isPrivateApi: false,
            showHashesWithNoDetections: true
        }, function (err, result) {
            //console.info(JSON.stringify(result, null, 4));
            //console.info(JSON.stringify(err, null, 4));
            expect(err).to.be.null;
            expect(result).to.deep.equal(
                [
                    {
                        "entity": {
                            "type": "hash",
                            "types": [
                                "hash", "sha256"
                            ],
                            "value": "7e3485f5edd48ffce37b0b0b735cd97f5ab514aa8dc4d6bc16cc4c40fb3fb570",
                            "isSHA256": true
                        },
                        "data": {
                            "summary": [
                                "0 <i class='fa fa-bug integration-text-bold-color'></i> / 62"
                            ],
                            "details": {
                                "scans": {
                                    "Bkav": {
                                        "detected": false,
                                        "version": "1.3.0.9282",
                                        "result": null,
                                        "update": "20170727"
                                    },
                                    "MicroWorld-eScan": {
                                        "detected": false,
                                        "version": "12.0.250.0",
                                        "result": null,
                                        "update": "20170727"
                                    },
                                    "nProtect": {
                                        "detected": false,
                                        "version": "2017-07-27.01",
                                        "result": null,
                                        "update": "20170727"
                                    }
                                },
                                "scan_id": "7e3485f5edd48ffce37b0b0b735cd97f5ab514aa8dc4d6bc16cc4c40fb3fb570-1501185873",
                                "sha1": "c21dc47d57437909f9cac14e786c77e9f3e78e56",
                                "resource": "7e3485f5edd48ffce37b0b0b735cd97f5ab514aa8dc4d6bc16cc4c40fb3fb570",
                                "response_code": 1,
                                "scan_date": "2017-07-27 20:04:33",
                                "permalink": "https://www.virustotal.com/file/7e3485f5edd48ffce37b0b0b735cd97f5ab514aa8dc4d6bc16cc4c40fb3fb570/analysis/1501185873/",
                                "verbose_msg": "Scan finished, information embedded",
                                "total": 62,
                                "positives": 0,
                                "sha256": "7e3485f5edd48ffce37b0b0b735cd97f5ab514aa8dc4d6bc16cc4c40fb3fb570",
                                "md5": "e87c6a38e61a712c48025a6ad54c1113",
                                "type": "file"
                            }
                        }
                    }
                ]
            );
            done();
        });
    });

    it('should not lookup hash is "lookupFiles" is false', function (done) {
        integration.doLookup([{
            type: 'hash',
            types: ['hash', 'sha256'],
            value: '7e3485f5edd48ffce37b0b0b735cd97f5ab514aa8dc4d6bc16cc4c40fb3fb570',
            isSHA256: true
        }], {
            apiKey: 'fakekey',
            lookupIps: false,
            lookupFiles: false,
            isPrivateApi: false,
            showHashesWithNoDetections: true
        }, function (err, result) {
            // console.info(JSON.stringify(result, null, 4));
            // console.info(JSON.stringify(err, null, 4));
            expect(err).to.be.null;
            expect(result).to.deep.equal([]);
            done();
        });
    });

    it('should cache miss for hash without result.', function (done) {
        nock('https://www.virustotal.com')
            .post('/vtapi/v2/file/report', function (body) {
                if (body.apikey === 'cache miss for hash') {
                    return true;
                }
                return false;
            })
            .reply(200, {
                "response_code": 0,
                "resource": "7e3485f5edd48ffce37b0b0b735cd97f5ab514aa8dc4d6bc16cc4c40fb3fb570",
                "verbose_msg": "The requested resource is not among the finished, queued or pending scans"
            });

        integration.doLookup([{
            type: 'hash',
            types: ['hash', 'sha256'],
            value: '7e3485f5edd48ffce37b0b0b735cd97f5ab514aa8dc4d6bc16cc4c40fb3fb570',
            isSHA256: true
        }], {
            apiKey: 'cache miss for hash',
            lookupIps: false,
            lookupFiles: true,
            isPrivateApi: false,
            showHashesWithNoDetections: true
        }, function (err, result) {
            // console.info(JSON.stringify(result, null, 4));
            // console.info(JSON.stringify(err, null, 4));
            // expect(err).to.be.null;
            expect(result).to.deep.equal(
                [
                    {
                        "entity": {
                            "type": "hash",
                            "types": [
                                "hash", "sha256"
                            ],
                            "value": "7e3485f5edd48ffce37b0b0b735cd97f5ab514aa8dc4d6bc16cc4c40fb3fb570",
                            "isSHA256": true
                        },
                        "data": null
                    }
                ]
            );
            done();
        });
    });

    it('should show hash with no detections if showHashesWithNoDetections=true', function (done) {
        nock('https://www.virustotal.com')
            .post('/vtapi/v2/file/report', function (body) {
                if (body.apikey === 'showHashesWithNoDetections=true test') {
                    return true;
                }
                return false;
            })
            .reply(200, {
                    "scans": {},
                    "scan_id": "7e3485f5edd48ffce37b0b0b735cd97f5ab514aa8dc4d6bc16cc4c40fb3fb570-1501185873",
                    "sha1": "c21dc47d57437909f9cac14e786c77e9f3e78e56",
                    "resource": "7e3485f5edd48ffce37b0b0b735cd97f5ab514aa8dc4d6bc16cc4c40fb3fb570",
                    "response_code": 1,
                    "scan_date": "2017-07-27 20:04:33",
                    "permalink": "https://www.virustotal.com/file/7e3485f5edd48ffce37b0b0b735cd97f5ab514aa8dc4d6bc16cc4c40fb3fb570/analysis/1501185873/",
                    "verbose_msg": "Scan finished, information embedded",
                    "total": 0,
                    "positives": 0,
                    "sha256": "7e3485f5edd48ffce37b0b0b735cd97f5ab514aa8dc4d6bc16cc4c40fb3fb570",
                    "md5": "e87c6a38e61a712c48025a6ad54c1113"
                }
            );

        integration.doLookup([{
            type: 'hash',
            types: ['hash', 'sha256'],
            value: '7e3485f5edd48ffce37b0b0b735cd97f5ab514aa8dc4d6bc16cc4c40fb3fb570',
            isSHA256: true
        }], {
            apiKey: 'showHashesWithNoDetections=true test',
            lookupIps: false,
            lookupFiles: true,
            isPrivateApi: false,
            showHashesWithNoDetections: true
        }, function (err, result) {
            // console.info(JSON.stringify(result, null, 4));
            // console.info(JSON.stringify(err, null, 4));
            // expect(err).to.be.null;
            expect(result).to.deep.equal(
                [
                    {
                        "entity": {
                            "type": "hash",
                            "types": [
                                "hash", "sha256"
                            ],
                            "value": "7e3485f5edd48ffce37b0b0b735cd97f5ab514aa8dc4d6bc16cc4c40fb3fb570",
                            "isSHA256": true
                        },
                        "data": {
                            "summary": [
                                "0 <i class='fa fa-bug integration-text-bold-color'></i> / 0"
                            ],
                            "details": {
                                "scans": {},
                                "scan_id": "7e3485f5edd48ffce37b0b0b735cd97f5ab514aa8dc4d6bc16cc4c40fb3fb570-1501185873",
                                "sha1": "c21dc47d57437909f9cac14e786c77e9f3e78e56",
                                "resource": "7e3485f5edd48ffce37b0b0b735cd97f5ab514aa8dc4d6bc16cc4c40fb3fb570",
                                "response_code": 1,
                                "scan_date": "2017-07-27 20:04:33",
                                "permalink": "https://www.virustotal.com/file/7e3485f5edd48ffce37b0b0b735cd97f5ab514aa8dc4d6bc16cc4c40fb3fb570/analysis/1501185873/",
                                "verbose_msg": "Scan finished, information embedded",
                                "total": 0,
                                "positives": 0,
                                "sha256": "7e3485f5edd48ffce37b0b0b735cd97f5ab514aa8dc4d6bc16cc4c40fb3fb570",
                                "md5": "e87c6a38e61a712c48025a6ad54c1113",
                                "type": "file"
                            }
                        }
                    }
                ]
            );
            done();
        });
    });

    it('should not show hash with no detections if showHashesWithNoDetections=false', function (done) {
        nock('https://www.virustotal.com')
            .post('/vtapi/v2/file/report', function (body) {
                if (body.apikey === 'showHashesWithNoDetections=false test') {
                    return true;
                }
                return false;
            })
            .reply(200, {
                    "scans": {},
                    "scan_id": "7e3485f5edd48ffce37b0b0b735cd97f5ab514aa8dc4d6bc16cc4c40fb3fb570-1501185873",
                    "sha1": "c21dc47d57437909f9cac14e786c77e9f3e78e56",
                    "resource": "7e3485f5edd48ffce37b0b0b735cd97f5ab514aa8dc4d6bc16cc4c40fb3fb570",
                    "response_code": 1,
                    "scan_date": "2017-07-27 20:04:33",
                    "permalink": "https://www.virustotal.com/file/7e3485f5edd48ffce37b0b0b735cd97f5ab514aa8dc4d6bc16cc4c40fb3fb570/analysis/1501185873/",
                    "verbose_msg": "Scan finished, information embedded",
                    "total": 0,
                    "positives": 0,
                    "sha256": "7e3485f5edd48ffce37b0b0b735cd97f5ab514aa8dc4d6bc16cc4c40fb3fb570",
                    "md5": "e87c6a38e61a712c48025a6ad54c1113"
                }
            );

        integration.doLookup([{
            type: 'hash',
            types: ['hash', 'sha256'],
            value: '7e3485f5edd48ffce37b0b0b735cd97f5ab514aa8dc4d6bc16cc4c40fb3fb570',
            isSHA256: true
        }], {
            apiKey: 'showHashesWithNoDetections=false test',
            lookupIps: false,
            lookupFiles: true,
            isPrivateApi: false,
            showHashesWithNoDetections: false
        }, function (err, result) {
            // console.info(JSON.stringify(result, null, 4));
            // console.info(JSON.stringify(err, null, 4));
            // expect(err).to.be.null;
            expect(result).to.deep.equal(
                [
                    {
                        "entity": {
                            "type": "hash",
                            "types": [
                                "hash", "sha256"
                            ],
                            "value": "7e3485f5edd48ffce37b0b0b735cd97f5ab514aa8dc4d6bc16cc4c40fb3fb570",
                            "isSHA256": true
                        },
                        "data": null
                    }
                ]
            );
            done();
        });
    });

    it('should remove duplicate hashes in final lookup request.', function (done) {
        nock('https://www.virustotal.com')
            .post('/vtapi/v2/file/report', function (body) {
                if (body.apikey === 'remove duplicate hash test') {
                    expect(body.resource).to.equal('7e3485f5edd48ffce37b0b0b735cd97f5ab514aa8dc4d6bc16cc4c40fb3fb570');
                    return true;
                }
                return false;
            })
            .reply(200, {
                "response_code": 0,
                "resource": "7e3485f5edd48ffce37b0b0b735cd97f5ab514aa8dc4d6bc16cc4c40fb3fb570",
                "verbose_msg": "The requested resource is not among the finished, queued or pending scans"
            });

        integration.doLookup([{
            type: 'hash',
            types: ['hash', 'sha256'],
            value: '7e3485f5edd48ffce37b0b0b735cd97f5ab514aa8dc4d6bc16cc4c40fb3fb570',
            isSHA256: true
        }, {
            type: 'hash',
            types: ['hash', 'sha256'],
            value: '7E3485f5edd48ffce37b0b0b735cd97f5ab514aa8dc4d6bc16cc4c40fb3fb570',
            isSHA256: true
        }, {
            type: 'hash',
            types: ['hash', 'sha256'],
            value: '7e3485f5edd48ffce37b0b0b735cd97f5ab514aa8dc4d6bc16cc4c40fb3fb570',
            isSHA256: true
        }, {
            type: 'hash',
            types: ['hash', 'sha256'],
            value: '7e3485f5edd48ffce37b0b0b735cd97f5ab514aa8dc4d6bc16cc4c40fb3FB570',
            isSHA256: true
        }], {
            apiKey: 'remove duplicate hash test',
            lookupIps: false,
            lookupFiles: true,
            isPrivateApi: false,
            showHashesWithNoDetections: true
        }, function (err, result) {
            done();
        });
    });

    it('should group hash lookups into 4 if "isPrivateApi" is false', function (done) {
        nock('https://www.virustotal.com')
            .post('/vtapi/v2/file/report', function (body) {
                if (body.apikey === 'isPrivateApi=false grouping test') {
                    expect(body.resource).to.equal('7e3485f5edd48ffce37b0b0b735cd97f5ab514aa8dc4d6bc16cc4c40fb3fb570, ' +
                        '7e3485f5edd48ffce37b0b0b735cd97f5ab514aa8dc4d6bc16cc4c40fb3fb571, ' +
                        '7e3485f5edd48ffce37b0b0b735cd97f5ab514aa8dc4d6bc16cc4c40fb3fb572, ' +
                        '7e3485f5edd48ffce37b0b0b735cd97f5ab514aa8dc4d6bc16cc4c40fb3fb573');
                    return true;
                } else {
                    return false;
                }
            })
            .reply(200, [
                {
                    "response_code": 0,
                    "resource": "7e3485f5edd48ffce37b0b0b735cd97f5ab514aa8dc4d6bc16cc4c40fb3fb570",
                    "verbose_msg": "The requested resource is not among the finished, queued or pending scans"
                },
                {
                    "response_code": 0,
                    "resource": "7e3485f5edd48ffce37b0b0b735cd97f5ab514aa8dc4d6bc16cc4c40fb3fb571",
                    "verbose_msg": "The requested resource is not among the finished, queued or pending scans"
                },
                {
                    "response_code": 0,
                    "resource": "7e3485f5edd48ffce37b0b0b735cd97f5ab514aa8dc4d6bc16cc4c40fb3fb572",
                    "verbose_msg": "The requested resource is not among the finished, queued or pending scans"
                },
                {
                    "response_code": 0,
                    "resource": "7e3485f5edd48ffce37b0b0b735cd97f5ab514aa8dc4d6bc16cc4c40fb3fb573",
                    "verbose_msg": "The requested resource is not among the finished, queued or pending scans"
                }
            ]);

        nock('https://www.virustotal.com')
            .post('/vtapi/v2/file/report', function (body) {
                if (body.apikey === 'isPrivateApi=false grouping test') {
                    expect(body.resource).to.equal('7e3485f5edd48ffce37b0b0b735cd97f5ab514aa8dc4d6bc16cc4c40fb3fb574');
                    return true;
                } else {
                    return false;
                }
            })
            .reply(200, {
                "response_code": 0,
                "resource": "7e3485f5edd48ffce37b0b0b735cd97f5ab514aa8dc4d6bc16cc4c40fb3fb574",
                "verbose_msg": "The requested resource is not among the finished, queued or pending scans"
            });

        integration.doLookup([{
            type: 'hash',
            types: ['hash', 'sha256'],
            value: '7e3485f5edd48ffce37b0b0b735cd97f5ab514aa8dc4d6bc16cc4c40fb3fb570',
            isSHA256: true
        }, {
            type: 'hash',
            types: ['hash', 'sha256'],
            value: '7e3485f5edd48ffce37b0b0b735cd97f5ab514aa8dc4d6bc16cc4c40fb3fb571',
            isSHA256: true
        }, {
            type: 'hash',
            types: ['hash', 'sha256'],
            value: '7e3485f5edd48ffce37b0b0b735cd97f5ab514aa8dc4d6bc16cc4c40fb3fb572',
            isSHA256: true
        }, {
            type: 'hash',
            types: ['hash, sha256'],
            value: '7e3485f5edd48ffce37b0b0b735cd97f5ab514aa8dc4d6bc16cc4c40fb3fb573',
            isSHA256: true
        }, {
            type: 'hash',
            types: ['hash, sha256'],
            value: '7e3485f5edd48ffce37b0b0b735cd97f5ab514aa8dc4d6bc16cc4c40fb3fb574',
            isSHA256: true
        }], {
            apiKey: 'isPrivateApi=false grouping test',
            lookupIps: false,
            lookupFiles: true,
            isPrivateApi: false,
            showHashesWithNoDetections: true
        }, function (err, result) {
            // console.info(JSON.stringify(result, null, 4));
            // console.info(JSON.stringify(err, null, 4));
            // expect(err).to.be.null;
            // expect(result).to.deep.equal([]);
            done();
        });
    });

    it('should lookup ip', function (done) {
        nock('https://www.virustotal.com')
            .get('/vtapi/v2/ip-address/report')
            .query({
                "apikey": 'ip-lookup',
                "ip": '200.2.2.2'
            })
            .reply(200, {
                    "detected_urls": [],
                    "asn": "27676",
                    "country": "CL",
                    "response_code": 1,
                    "as_owner": "Atacama Large Millimeter Array",
                    "resolutions": [
                        {
                            "last_resolved": "2015-04-26 00:00:00",
                            "hostname": "gasve.info"
                        },
                        {
                            "last_resolved": "2016-05-03 00:00:00",
                            "hostname": "sgnotify.com"
                        },
                        {
                            "last_resolved": "2015-03-03 00:00:00",
                            "hostname": "terasworld.com"
                        }
                    ],
                    "verbose_msg": "IP address in dataset"
                }
            );


        integration.doLookup([{
            type: 'IPv4',
            types: ['IP', 'IPv4'],
            value: '200.2.2.2',
            isIPv4: true
        }], {
            apiKey: 'ip-lookup',
            lookupIps: true,
            lookupFiles: false,
            isPrivateApi: false,
            showHashesWithNoDetections: true
        }, function (err, result) {
            // console.info(JSON.stringify(result, null, 4));
            // console.info(JSON.stringify(err, null, 4));
            expect(err).to.be.null;
            expect(result).to.deep.equal(
                [
                    {
                        "entity": {
                            "type": "IPv4",
                            "types": [
                                "IP",
                                "IPv4"
                            ],
                            "value": "200.2.2.2",
                            "isIPv4": true
                        },
                        "data": {
                            "summary": [
                                "3 <i class='bts bt-globe integration-text-bold-color'></i>",
                                "0 <i class='fa fa-bug integration-text-bold-color'></i> / 0"
                            ],
                            "details": {
                                "type": "ip",
                                "overallPositives": 0,
                                "overallTotal": 0,
                                "overallPercent": "NA",
                                "detectedUrlsPositive": 0,
                                "detectedUrlsTotal": 0,
                                "detectedCommunicatingSamplesPositive": 0,
                                "detectedCommunicatingSamplesTotal": 0,
                                "detectedDownloadedSamplesPositive": 0,
                                "detectedDownloadedSamplesTotal": 0,
                                "detectedReferrerSamplesPositive": 0,
                                "detectedReferrerSamplesTotal": 0,
                                "numResolutions": 3,
                                "detectedUrls": [],
                                "resolutions": [
                                    {
                                        "last_resolved": "2015-04-26 00:00:00",
                                        "hostname": "gasve.info"
                                    },
                                    {
                                        "last_resolved": "2016-05-03 00:00:00",
                                        "hostname": "sgnotify.com"
                                    },
                                    {
                                        "last_resolved": "2015-03-03 00:00:00",
                                        "hostname": "terasworld.com"
                                    }
                                ],
                                "detectedUrlsPercent": "NA",
                                "detectedCommunicatingSamplesPercent": "NA",
                                "detectedDownloadedSamplesPercent": "NA",
                                "detectedReferrerSamplesPercent": "NA"
                            }
                        }
                    }
                ]
            );
            done();
        });
    });

    it('should not lookup ip if "lookupIps=false"', function (done) {
        nock('https://www.virustotal.com')
            .get('/vtapi/v2/ip-address/report')
            .query({
                "apikey": 'ip-lookup',
                "ip": '200.2.2.2'
            })
            .reply(200, {
                    "detected_urls": [],
                    "asn": "27676",
                    "country": "CL",
                    "response_code": 1,
                    "as_owner": "Atacama Large Millimeter Array",
                    "resolutions": [
                        {
                            "last_resolved": "2015-04-26 00:00:00",
                            "hostname": "gasve.info"
                        },
                        {
                            "last_resolved": "2016-05-03 00:00:00",
                            "hostname": "sgnotify.com"
                        },
                        {
                            "last_resolved": "2015-03-03 00:00:00",
                            "hostname": "terasworld.com"
                        }
                    ],
                    "verbose_msg": "IP address in dataset"
                }
            );


        integration.doLookup([{
            type: 'IPv4',
            types: ['IP', 'IPv4'],
            value: '200.2.2.2',
            isIPv4: true
        }], {
            apiKey: 'ip-lookup',
            lookupIps: false,
            lookupFiles: false,
            isPrivateApi: false,
            showHashesWithNoDetections: true
        }, function (err, result) {
            // console.info(JSON.stringify(result, null, 4));
            // console.info(JSON.stringify(err, null, 4));
            expect(err).to.be.null;
            expect(result).to.deep.equal([]);
            done();
        });
    });

    it('should cache ip lookup miss', function (done) {
        nock('https://www.virustotal.com')
            .get('/vtapi/v2/ip-address/report')
            .query({
                "apikey": 'ip-lookup-miss',
                "ip": '56.2.3.1'
            })
            .reply(200, {
                    "response_code": 0,
                    "verbose_msg": "Missing IP address"
                }
            );


        integration.doLookup([{
            type: 'IPv4',
            types: ['IP', 'IPv4'],
            value: '56.2.3.1',
            isIPv4: true
        }], {
            apiKey: 'ip-lookup-miss',
            lookupIps: true,
            lookupFiles: false,
            isPrivateApi: false,
            showHashesWithNoDetections: true
        }, function (err, result) {
            // console.info(JSON.stringify(result, null, 4));
            // console.info(JSON.stringify(err, null, 4));
            expect(err).to.be.null;
            expect(result).to.deep.equal([
                {
                    "entity": {
                        "type": "IPv4",
                        "types": [
                            "IP",
                            "IPv4"
                        ],
                        "value": "56.2.3.1",
                        "isIPv4": true
                    },
                    "data": null
                }

            ]);
            done();
        });
    });
});
