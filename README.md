# Polarity VirusTotal Integration

Polarity's VirusTotal integration gives users access to automated MD5, SHA1, SHA256, and IPv4 lookups within VirusTotal.

VirusTotal is a free service that analyzes suspicious files and URLs and facilitates the quick detection of viruses, worms, trojans, and all kinds of malware.  For more information about VirusTotal please visit https://www.virustotal.com/

| ![image](https://cloud.githubusercontent.com/assets/306319/24308680/644b36b8-109f-11e7-929f-bbfb7a322622.png) | ![image](https://cloud.githubusercontent.com/assets/306319/24308814/de543ae0-109f-11e7-8498-f3d85d4bc093.png) |
|---|---|
|*VirusTotal Lookup of an MD5 Hash* | VirusTotal Lookup of an IPv4 Address |

> Note that the VirusTotal platform throttles lookups that make use of free public API keys to approximately four lookups a minute.

## VirusTotal Integration Options

### VirusTotal API Key

Your VirusTotal API Key (free or commercial)

## Lookup IP Addresses

If checked, the VirusTotal integration will send IPv4 addresses to VirusTotal for lookup.

### Lookup Files (Hashes)

If checked, the VirusTotal integration will send MD5, SHA1, and SHA256 hashes to VirusTotal for lookup.

### API Key Limit Reach Warning

If checked, the VirusTotal integration will display warnings in the notification window when you have hit the VirusTotal lookup limit for the api key you are currently using.

## Installation Instructions

1. Navigate to the [polarityio/virustotal releases page](https://github.com/polarityio/virustotal/releases).
2. Download the `tar.gz` file for the version of the integration you want to install (we typically recommend installing the latest version of the integration).
3. Upload the `tar.gz` file to your Polarity Server.
4. Move the `tar.gz` file to the Polarity Server integrations directory.

 ```bash
 mv <filename> /app/polarity-server/integrations
 ```

5. Once the file has been moved, navigate to the integrations folder:

 ```bash
 cd /app/polarity-server/integrations
 ```
  
6. Extract the tar file:

 ```bash
 tar -xzvf <filename>
 ```

6. Navigate into the extracted folder for the new integration:

 ```bash
cd <filename>
```

7. Install the integration's dependencies:

 ```bash
npm install
```

8. Ensure the integration directory is owned by the `polarityd` user
 
 ```bash
chown -R polarityd:polarityd /app/polarity-server/integrations/virustotal
```

9. Restart your Polarity-Server

 ```bash
service polarityd restart
```

10. Navigate to the integrations page in Polarity-Web to configure the integration.

### Installing via GIT Clone

1. Navigate to the integrations folder:

 ```bash
cd /app/polarity-server/integrations
```

2. Clone a specific version of the virustotal repo using git:

 ```bash
git clone --branch <version> https://github.com/polarityio/virustotal.git
```

3. Change into the integration directory

 ```bash
cd wikipedia
```

4. Use `npm` to install the integration's dependencies

 ```bash
npm install
```

5.  Ensure the integration directory is owned by the `polarityd` user

 ```bash
chown -R polarityd:polarityd /app/polarity-server/integrations/virustotal
```

6. Restart your Polarity-Server

 ```bash
service polarityd restart
```

7. Navigate to the integrations page in Polarity-Web to configure the integration

## Polarity

Polarity is a memory-augmentation platform that improves and accelerates analyst decision making.  For more information about the Polarity platform please see: 

https://polarity.io/
