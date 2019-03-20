'use strict';

const chai = require('chai');
const expect = chai.expect;
const nock = require('nock');
const integration = require('../integration');

describe('doLookup()', function () {
    before(function (done) {
        integration.startup({
            trace: function (msg) {
                //console.info(msg)
            },
            info: function (msg) {
                //console.info(msg)
            },
            debug: function (msg) {
                //console.info(msg)
            },
            error: function (msg) {
                console.info(msg)
            }
        });

        nock('https://www.virustotal.com')
            .post('/vtapi/v2/file/report', {
                "apikey": 'fakekey',
                "resource": '7e3485f5edd48ffce37b0b0b735cd97f5ab514aa8dc4d6bc16cc4c40fb3fb570'
            })
            .times(1)
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
                                `0 <svg aria-hidden="true" focusable="false" data-prefix="fas" data-icon="bug" role="img" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512" class="svg-inline--fa fa-bug fa-w-16"><path fill="currentColor" d="M511.988 288.9c-.478 17.43-15.217 31.1-32.653 31.1H424v16c0 21.864-4.882 42.584-13.6 61.145l60.228 60.228c12.496 12.497 12.496 32.758 0 45.255-12.498 12.497-32.759 12.496-45.256 0l-54.736-54.736C345.886 467.965 314.351 480 280 480V236c0-6.627-5.373-12-12-12h-24c-6.627 0-12 5.373-12 12v244c-34.351 0-65.886-12.035-90.636-32.108l-54.736 54.736c-12.498 12.497-32.759 12.496-45.256 0-12.496-12.497-12.496-32.758 0-45.255l60.228-60.228C92.882 378.584 88 357.864 88 336v-16H32.666C15.23 320 .491 306.33.013 288.9-.484 270.816 14.028 256 32 256h56v-58.745l-46.628-46.628c-12.496-12.497-12.496-32.758 0-45.255 12.498-12.497 32.758-12.497 45.256 0L141.255 160h229.489l54.627-54.627c12.498-12.497 32.758-12.497 45.256 0 12.496 12.497 12.496 32.758 0 45.255L424 197.255V256h56c17.972 0 32.484 14.816 31.988 32.9zM257 0c-61.856 0-112 50.144-112 112h224C369 50.144 318.856 0 257 0z" class=""></path></svg>/ 62`
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
                                `0 <svg aria-hidden="true" focusable="false" data-prefix="fas" data-icon="bug" role="img" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512" class="svg-inline--fa fa-bug fa-w-16"><path fill="currentColor" d="M511.988 288.9c-.478 17.43-15.217 31.1-32.653 31.1H424v16c0 21.864-4.882 42.584-13.6 61.145l60.228 60.228c12.496 12.497 12.496 32.758 0 45.255-12.498 12.497-32.759 12.496-45.256 0l-54.736-54.736C345.886 467.965 314.351 480 280 480V236c0-6.627-5.373-12-12-12h-24c-6.627 0-12 5.373-12 12v244c-34.351 0-65.886-12.035-90.636-32.108l-54.736 54.736c-12.498 12.497-32.759 12.496-45.256 0-12.496-12.497-12.496-32.758 0-45.255l60.228-60.228C92.882 378.584 88 357.864 88 336v-16H32.666C15.23 320 .491 306.33.013 288.9-.484 270.816 14.028 256 32 256h56v-58.745l-46.628-46.628c-12.496-12.497-12.496-32.758 0-45.255 12.498-12.497 32.758-12.497 45.256 0L141.255 160h229.489l54.627-54.627c12.498-12.497 32.758-12.497 45.256 0 12.496 12.497 12.496 32.758 0 45.255L424 197.255V256h56c17.972 0 32.484 14.816 31.988 32.9zM257 0c-61.856 0-112 50.144-112 112h224C369 50.144 318.856 0 257 0z" class=""></path></svg>/ 0`
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
                                `<svg viewBox="0 0 496 512" xmlns="http://www.w3.org/2000/svg" role="img" aria-hidden="true" data-icon="globe" data-prefix="fas" id="ember882" class="svg-inline--fa fa-globe fa-w-16 fa-fw  undefined ember-view"><path fill="currentColor" d="M336.5 160C322 70.7 287.8 8 248 8s-74 62.7-88.5 152h177zM152 256c0 22.2 1.2 43.5 3.3 64h185.3c2.1-20.5 3.3-41.8 3.3-64s-1.2-43.5-3.3-64H155.3c-2.1 20.5-3.3 41.8-3.3 64zm324.7-96c-28.6-67.9-86.5-120.4-158-141.6 24.4 33.8 41.2 84.7 50 141.6h108zM177.2 18.4C105.8 39.6 47.8 92.1 19.3 160h108c8.7-56.9 25.5-107.8 49.9-141.6zM487.4 192H372.7c2.1 21 3.3 42.5 3.3 64s-1.2 43-3.3 64h114.6c5.5-20.5 8.6-41.8 8.6-64s-3.1-43.5-8.5-64zM120 256c0-21.5 1.2-43 3.3-64H8.6C3.2 212.5 0 233.8 0 256s3.2 43.5 8.6 64h114.6c-2-21-3.2-42.5-3.2-64zm39.5 96c14.5 89.3 48.7 152 88.5 152s74-62.7 88.5-152h-177zm159.3 141.6c71.4-21.2 129.4-73.7 158-141.6h-108c-8.8 56.9-25.6 107.8-50 141.6zM19.3 352c28.6 67.9 86.5 120.4 158 141.6-24.4-33.8-41.2-84.7-50-141.6h-108z"></path></svg> 3`,
                                `0 <svg aria-hidden="true" focusable="false" data-prefix="fas" data-icon="bug" role="img" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512" class="svg-inline--fa fa-bug fa-w-16"><path fill="currentColor" d="M511.988 288.9c-.478 17.43-15.217 31.1-32.653 31.1H424v16c0 21.864-4.882 42.584-13.6 61.145l60.228 60.228c12.496 12.497 12.496 32.758 0 45.255-12.498 12.497-32.759 12.496-45.256 0l-54.736-54.736C345.886 467.965 314.351 480 280 480V236c0-6.627-5.373-12-12-12h-24c-6.627 0-12 5.373-12 12v244c-34.351 0-65.886-12.035-90.636-32.108l-54.736 54.736c-12.498 12.497-32.759 12.496-45.256 0-12.496-12.497-12.496-32.758 0-45.255l60.228-60.228C92.882 378.584 88 357.864 88 336v-16H32.666C15.23 320 .491 306.33.013 288.9-.484 270.816 14.028 256 32 256h56v-58.745l-46.628-46.628c-12.496-12.497-12.496-32.758 0-45.255 12.498-12.497 32.758-12.497 45.256 0L141.255 160h229.489l54.627-54.627c12.498-12.497 32.758-12.497 45.256 0 12.496 12.497 12.496 32.758 0 45.255L424 197.255V256h56c17.972 0 32.484 14.816 31.988 32.9zM257 0c-61.856 0-112 50.144-112 112h224C369 50.144 318.856 0 257 0z" class=""></path></svg>/ 0`
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
