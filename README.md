# Polarity VirusTotal Integration

Polarity's VirusTotal integration gives users access to automated MD5, SHA1, SHA256, and IPv4 lookups within VirusTotal.

VirusTotal is a free service that analyzes suspicious files and URLs and facilitates the quick detection of viruses, worms, trojans, and all kinds of malware.  For more information about VirusTotal please visit https://www.virustotal.com/

| ![image](https://user-images.githubusercontent.com/306319/54649711-be923400-4a81-11e9-8bbb-2bfd99bb4394.png) | ![image](https://user-images.githubusercontent.com/306319/54649751-da95d580-4a81-11e9-8d8a-ebf39b97e864.png) |
|---|---|
|*VirusTotal Lookup of an MD5 Hash* | *VirusTotal Lookup of an IPv4 Address* |

## VirusTotal Integration Options

### VirusTotal API Key

Your VirusTotal API Key (free or commercial)

> Note that the VirusTotal platform throttles lookups that make use of free public API keys to approximately four lookups a minute.

### Show All File Scanner AV Results

Default: true

If checked, the integration will show all AV scanner results for files (hashes) even if the AV scanner did not detect the sample as a positive detection. Default is to show all results. Uncheck to only show positive AV detections in the scanner results table.

### Show Files (Hashes) with No Detections

Default: false

If checked, the integration will show results for files that have no positive detections.

### Show IP Addresses with No Detections

Default: false

If checked, the integration will show results for IP addresses that have no positive detections. By default, the integration will not show IP reports with no positive detections even if the IP address in question has a resolved hostname.

### API Key Lookup Limit Reached Warning Message

Displays a warning in the Notification Window if you have reached your VirusTotal API key lookup limit.

### Lookup Throttle Duration

The amount of time in minutes the integration will throttle your VirusTotal lookups in the event that you hit your lookup limit. Once throttling has started no lookups for your configured API key will be made until the throttle time has passed. Defaults to 1 minute.

### Lookup Throttle Warning Message

If checked, the integration will display a warning message in the overlay window when your VirusTotal lookups are being throttled.  Only one message will be shown per throttle duration.

## Installation Instructions

Installation instructions for integrations are provided on the [PolarityIO GitHub Page](https://polarityio.github.io/).

## Polarity

Polarity is a memory-augmentation platform that improves and accelerates analyst decision making.  For more information about the Polarity platform please see:

https://polarity.io/
