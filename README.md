# BubblePop - Bubble.io ElasticSearch decryptor 

A Burp Suite extension that enables security testing of Bubble.io applications by automatically decrypting and re-encrypting their Elasticsearch payload data.

## Description

BubblePop is a specialized Burp Suite extension designed for security researchers and penetration testers working with Bubble.io applications. Bubble.io applications encrypt their Elasticsearch database queries. This extension automatically handles the decryption & re-encryption, allowing security professionals to analyze and modify database operations during security assessments.

The extension provides:
- Automatic detection and decryption of Bubble.io ElasticSearch encrypted payloads based on the Bubble `AppName`
- Real-time payload inspection through a dedicated message editor tab
- Seamless re-encryption of modified payloads for request manipulation


## Installation

### Requirements
- Burp Suite Professional (2023.10+)
- Jython support enabled in Burp Suite

### Steps
1. Download the `BubblePop.py` file from this repository
2. In Burp Suite, navigate to **Extensions** → **Installed** → **Add**
3. Select **Extension type**: Python
4. Choose the downloaded `BubblePop.py` file
5. Click **Next** to load the extension
6. Verify installation by checking for the "BubblePop" tab in Burp's main interface

## Configuration

1. Navigate to the **BubblePop** tab in Burp Suite's main interface
2. Enter the target Bubble.io application name in the configuration field
3. Click **Save** to apply the configuration

<img width="615" height="212" alt="image" src="https://github.com/user-attachments/assets/e61d7c2a-53b4-4652-b6dd-02c9d1dad3e0" />


## Usage Instructions

### Basic Usage
1. Configure the extension with your target Bubble.io `AppName`
2. Use Burp's Proxy to intercept traffic from the Bubble.io application
3. When encrypted Elasticsearch requests are intercepted, look for the **BubblePop** tab in the message editor
4. The tab will display the decrypted database queries and JSON data

<img width="1037" height="491" alt="image" src="https://github.com/user-attachments/assets/74bfc748-b384-46b1-993c-740e354e22b4" />

<img width="478" height="257" alt="image" src="https://github.com/user-attachments/assets/dd45247d-50a1-4e09-8655-53150de65883" />

5. Modify the decrypted content as needed for your security testing
6. Forward or repeat the request - the extension automatically re-encrypts your modifications



## Credits

This extension implements the encryption research from [demon-i386/pop_n_bubble](https://github.com/demon-i386/pop_n_bubble). All credit for the original cryptographic analysis and Python implementation goes to the researchers at that project.


## Disclaimer

For authorized security testing only. Don't use this for malicious purposes.


## Version History

- **v2.0**: Montoya API migration, background threading, improved error handling
- **v1.0**: Initial release with basic decryption functionality
