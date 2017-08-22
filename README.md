# Polarity VirusTotal Integration

Polarity's VirusTotal integration gives users access to automated MD5, SHA1, SHA256, and IPv4 lookups within VirusTotal.

VirusTotal is a free service that analyzes suspicious files and URLs and facilitates the quick detection of viruses, worms, trojans, and all kinds of malware.  For more information about VirusTotal please visit https://www.virustotal.com/

| ![image](https://cloud.githubusercontent.com/assets/306319/24308680/644b36b8-109f-11e7-929f-bbfb7a322622.png) | ![image](https://cloud.githubusercontent.com/assets/306319/24308814/de543ae0-109f-11e7-8498-f3d85d4bc093.png) |
|---|---|
|*VirusTotal Lookup of an MD5 Hash* | *VirusTotal Lookup of an IPv4 Address* |

## VirusTotal Integration Options

### VirusTotal API Key

Your VirusTotal API Key (free or commercial)

> Note that the VirusTotal platform throttles lookups that make use of free public API keys to approximately four lookups a minute.

### Lookup IP Addresses

If checked, the VirusTotal integration will send IPv4 addresses to VirusTotal for lookup.

### Lookup Files (Hashes)

If checked, the VirusTotal integration will send MD5, SHA1, and SHA256 hashes to VirusTotal for lookup.

### Show Files (Hashes) with No Detections

Default: false

If checked, the VirusTotal integration will show files in the notification overlay that have no detections.

### API Key Limit Reach Warning

If checked, the VirusTotal integration will display warnings in the notification overlay when you have hit the VirusTotal lookup limit for the api key you are currently using.

## Installation Instructions

Installation instructions for integrations are provided on the [PolarityIO GitHub Page](https://polarityio.github.io/).

## Polarity

Polarity is a memory-augmentation platform that improves and accelerates analyst decision making.  For more information about the Polarity platform please see: 

https://polarity.io/
