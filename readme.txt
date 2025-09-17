# BlackHaven Messenger

BlackHaven Messenger is a WordPress plugin that enables near real-time messaging functionality using your WordPress install as a backend. The plugin is only the API part of the secure messaging. The plugin requires an application to handle the key generation and exchanges.

Right now the plugin is in active development and is not ready for production.

## Features

- Enables near realtime messaging using the built in REST API.
- Easy to setup and configure.
- Support for one-on-one communication.
- Support for group communication.
- Support for file transfers.
- Support for RSA-4096 encryption.

## Installation

1. Download the plugin ZIP file.
2. In your WordPress admin dashboard, go to **Plugins > Add New**.
3. Click **Upload Plugin** and select the ZIP file.
4. Click **Install Now** and then **Activate**.

## Usage

- After activation, a Messenger menu will appear in your WordPress admin area.
- Currently, usage of the messenger is only through the API. Check out the documentation (Need to add the documentation).

## Requirements

- WordPress 6.8.2 or higher
- PHP 8.0 or higher

## Frequently Asked Questions

**Q:** How can BlackHaven Messenger be secure and supported on shared servers? 
**A:** First off, we recommend at least VPS hosting but we reconize that VPS can be exspensive. The BlackHaven Messenger plugin for WordPress does not not have any pof the encryption keys stored on the server. This means that not even your server knows the content that is being shared.

**Q:** Is messaging private?  
**A:** Yes. All messages are stored securely and are only visible to participants.

**Q:** There are keys stored in the database in plain text, is this secure?  
**A:** Yes. All public keys are stored in the database in plain text. Access tokens and secure keys are hashed and there is no storage of any private keys on the server. 

**Q:** How are all key exchanges secure?
**A:** The common approach using the Diffie–Hellman key exchange process to keep things secure while exchanging keys.

## Support

Submit an issue here in the GitHub repo for the time being.

## Changelog

### 1.0.0
- Initial release

## ToDo
- Add option to notify the admins when settings have changed for the plugin.
- Adjust the security audit plugin to be relevant for the plugin. Not a whole site vulnerability scan.
- Look into adding an API scan feature for using WP Scan for clients without them needing to have the Securi plugin installed for the sake of security (why reivent the wheel)
- Look into making the QR code image in the connection tab for easier setup.
- Look into the type of message system we can use for realtime por near realtime? MQTT? Whatever we use should work on shared servers.
- Hashing the access token requires a user ID to be sent as well in the API. Is there any other way to do this effectively.
- Add hook for password reset and token removal.
- Look into issuing a new refresh token every so often in normal requests so that the refresh token revolves. This will require the any app using this to look for a new refreh token in just about every call.
- Allow for group messages to have a name.
- Add in file uploads... This needs to be thought out and needs to be secure!!!!
- In the app be sure to use a triple key system.
- Be sure to support key rotating (forward security) so new members in groups can not see older messages other than when they joined.
- Add the individual identity key(s) for a conversation in teh conversations payload.
- Add ability to send notes to ones self (start conversations with self). Right now, it errors out.
- Update API endpoints for starting a conversation to fall in line with conversations/private/start, etc and not endpoint hackery.
- Add getting started guide on activation to guide the user on what to do to get started.
- Audit usernames and display names for an email address. This is not recommended due to PII being exposed.
- IMPORTANT: Look into masking the user ID with a hash as well to protect against ID leak and work around attacks already exposed in WP.
- Send push to user when a user creates a conversation with them.
- Hide all endpoints and make sure they are not visible and or respond with a 404 unless a valid identify is provided.
- Can we use a zero trust proxy and custom API instead of WP-JSON?

## License

This plugin is licensed under the GPLv2 or later.