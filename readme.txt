# BlackHaven Messenger

BlackHaven Messenger is a WordPress plugin that enables near real-time messaging functionality using your WordPress install as a backend. Right now the plugin is in active development and is not ready for production.

## Features

- Enables near realtime messaging using the built in REST API.
- Easy to setup and configure.
- Support for one-on-one communication.
- Support for group communication.
- Support for file transfers.

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
**A:** Yes, all messages are stored securely and are only visible to participants. Encryption keys are never relayed or stored on the server.

## Support

Submit an issue here in the GitHub repo for the time being.

## Changelog

### 1.0.0
- Initial release

## ToDo
- Add option to notifiy the admins when settings have changed for the plugin.
- Adjust the security audit plugin to be relvent for the plugin. Not a whole site vulnerability scan.
- Look into adding an API scan feature for using WP Scan for clients without them needing to have the Securi plugin installed for the sake of security (why reivent the wheel)
- Look into making the QR code image in the connection tab for easier setup.
- Look into the type of message system we can use for realtime por near realtime? MQTT? Whatever we use should work on shared servers.
- Hashing the access token requires a user ID to be sent as well in the API. Is there any other way to do this effectivly.
- Add hook for password reset and token removal.
- Look into issuing a new refresh token every so often in normal requests so that the refresh token revolves. This will require the any app using this to look for a new refreh token in just about every call.
- Allow for groupo messages to have a name.

## License

This plugin is licensed under the GPLv2 or later.