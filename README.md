# Polarity VirusTotal Integration

Polarity's VirusTotal integration gives users access to automated MD5, SHA1, SHA256, IPv4, Domain, and URL lookups within VirusTotal and makes use of the v3.0 REST API.

VirusTotal is a service that analyzes suspicious files and URLs and facilitates the quick detection of viruses, worms, trojans, and all kinds of malware.  For more information about VirusTotal please visit https://www.virustotal.com/.

| ![](assets/integration-example-ip.png) |![](/assets/integration-example-md5.png)|![](assets/integration-example-url.png)
|---|---|--|
|*IP Address Example* |*Hash Example*| *Domain Example*|

## VirusTotal Integration Options

### VirusTotal API Key

Your VirusTotal Premium API Key

### Return Unscanned or Unseen Results

Default: true

If checked, the integration will return the summary tag "Has not been seen or scanned" if VT has not seen or scanned the indicator before.


### Show All File Scanner AV Results

Default: true

If checked, the integration will show all AV scanner results for files (hashes) even if the AV scanner did not detect the sample as a positive detection. Default is to show all results. Uncheck to only show positive AV detections in the scanner results table.

### Show Files (Hashes) with No Detections

Default: true

If checked, the integration will show results for files that have no positive detections.

### Show IP Addresses with No Detections

Default: true

If checked, the integration will show results for IP addresses that have no positive detections. By default, the integration will not show IP reports with no positive detections even if the IP address in question has a resolved hostname.

### Show Domains with No Detections

Default: true

If checked, the integration will show results for Domains that have no positive detections.

### Show Urls with No Detections

Default: true

If checked, the integration will show results for Urls that have no positive detections.


### API Key Lookup Limit Reached Warning Message

Default: false

Displays a warning in the Notification Window if you have reached your VirusTotal API key lookup limit.

### Lookup Throttle Duration

Default: 1 minute

The amount of time in minutes the integration will throttle your VirusTotal lookups in the event that you hit your lookup limit. Once throttling has started no lookups for your configured API key will be made until the throttle time has passed. Defaults to 1 minute.

### Lookup Throttle Warning Message

Default: true

If checked, the integration will display a warning message in the overlay window when your VirusTotal lookups are being throttled.  Only one message will be shown per throttle duration.

### Maximum number of hashes per lookup request

Set the maximum number of hashes per lookup that are allowed by your API key (defaults to 4)

### Indicator Blocklist

Comma delimited list of indicators you do not want looked up. List is an exact match (URL matches require the scheme). This option must be set to "Only Admins Can View and Edit".

### Domain and URL Blocklist Regex

Domains or URLs that match the given regex will not be looked up (if blank, all domains and URLS will be looked up). Note that the regex does not need to account for the scheme for URLs (i.e., the regex will match against the domain and subdomain of the URL. Do not wrap your regex in forward slashes. This option must be set to "Only Admins Can View and Edit".

### IP Blocklist Regex

IPs that match the given regex will not be looked up (if blank, all IPs will be looked up). Do not wrap your regex in forward slashes. This option must be set to "Only Admins Can View and Edit".

### Enable Baseline Investigation Threshold

If checked, the "Baseline Investigation Threshold Configuration" will be enabled. Defaults to unchecked. 

**This option must be set to "Only admins can view and edit".**

### Baseline Investigation Threshold Configuration

Comma delimited list of positive detection rules which can be used to customize the appearance of the positive detection summary tag.  Each rule consists of a number range (e.g., 5-10), followed by a colon and then the message to display.  Rules can optionally include a level of either "warn" or "danger" after the range. If the number of positive detections for an indicator falls within a specified range, the configured message is shown in a summary tag.  Default value is "0:No Detections,  1-3:warn:Suspicious - Review,  4-999:danger:Likely Malicious". 

**This option must be set to "Only admins can view and edit".**

#### Examples

Add the message "Possibly Benign" to any indicator with 0 detections:
```
0:Possibly Benign
```

Additionally, add the message "Suspicious" to any indicator with 1 to 4 positive detections: 
```
0:Possibly Benign, 1-4:Suspicious
```

Additionally, include a warning icon for "Suspicious" indicators:

```
0:Possibly Benign, 1-4:warn:Suspicious
```

Additionally, add the message "Likely Malicious" to any indicator with more than 5 positive detections and include a "danger" icon:

```
0:Possibly Benign, 1-4:warn:Suspicious, 5-999:danger:Likely Malicious
```


## Installation Instructions

Installation instructions for integrations are provided on the [PolarityIO GitHub Page](https://polarityio.github.io/).

## Polarity

Polarity is a memory-augmentation platform that improves and accelerates analyst decision making.  For more information about the Polarity platform please see:

https://polarity.io/
