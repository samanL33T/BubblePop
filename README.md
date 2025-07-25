# BubblePop

A Burp Suite extension for pentesting Bubble.io applications by decrypting and re-encrypting their Elasticsearch payload data.

## What it does

Bubble.io applications use Elasticsearch for data operations, but encrypt the queries and responses. This extension helps security researchers test these applications by automatically handling the encryption layer. When you intercept Elasticsearch requests from Bubble.io apps, it decrypts the payloads so you can see the actual database queries being executed. You can then modify the queries and the extension will re-encrypt them properly when forwarding the request.

## Installation

1. Save `BubblePop.py` somewhere on your system
2. In Burp Suite, go to Extensions → Installed → Add
3. Choose Extension type: Python and select the `BubblePop.py` file
4. Look for the "BubblePop" tab in Burp's main interface

## Setup

1. Go to the BubblePop tab in Burp
2. Enter the target Bubble.io app name 
3. Click Save

<img width="615" height="212" alt="image" src="https://github.com/user-attachments/assets/e61d7c2a-53b4-4652-b6dd-02c9d1dad3e0" />

## Usage

Once configured, browse to your target Bubble.io application. When Burp intercepts encrypted Elasticsearch requests, you'll see a new "BubblePop" tab in the Proxy/Repeater that shows the decrypted database queries and JSON data. You can edit these queries and send modified requests - the extension handles re-encryption automatically.

<img width="1037" height="491" alt="image" src="https://github.com/user-attachments/assets/74bfc748-b384-46b1-993c-740e354e22b4" />

<img width="478" height="257" alt="image" src="https://github.com/user-attachments/assets/dd45247d-50a1-4e09-8655-53150de65883" />


## Credits

This extension implements the encryption research from [demon-i386/pop_n_bubble](https://github.com/demon-i386/pop_n_bubble). All credit for the original cryptographic analysis and Python implementation goes to the researchers at that project.

## Disclaimer

For authorized security testing only. Don't use this for malicious purposes.
