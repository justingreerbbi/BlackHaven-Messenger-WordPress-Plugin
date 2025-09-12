# BlackHaven Messenger

BlackHaven Messenger is a WordPress plugin that enables real-time messaging functionality on your WordPress site. Enhance user engagement by allowing visitors, members, or customers to communicate seamlessly.

## Features

- Real-time messaging between users
- User-friendly chat interface
- Notifications for new messages
- Secure and private conversations
- Easy integration with WordPress user system
- Enhanced Security for the most secure enviroment
- E2EE 

## Installation

1. Download the plugin ZIP file.
2. In your WordPress admin dashboard, go to **Plugins > Add New**.
3. Click **Upload Plugin** and select the ZIP file.
4. Click **Install Now** and then **Activate**.

## Usage

- After activation, a Messenger widget will appear on your site.
- Users can start conversations by clicking the Messenger icon.
- Configure plugin settings under **Settings > BlackHaven Messenger**.

## Requirements

- WordPress 5.0 or higher
- PHP 7.2 or higher

## Frequently Asked Questions

**Q:** How can BlackHaven Messenger be secure and supported on shared servers? 
**A:** First off, we recommend at least VPS hosting but we reconize that VPS can be exspensive. The BlackHaven Messenger plugin for WordPress does not not have any pof the encryption keys stored on the server. This means that not even your server knows the content that is being shared.

**Q:** Is messaging private?  
**A:** Yes, all messages are stored securely and are only visible to participants. Encryption keys are never relayed or stored on the server.

## Support

For support, feature requests, or bug reports, please visit the [plugin support forum](https://wordpress.org/support/plugin/blackhaven-messenger) or contact the developer at support@blackhaven.local.

## Changelog

### 1.0.0
- Initial release

## ToDo
- Add option for API enable or disable
- Add option to notifiy the admins when settings have changed for the plugin.
- Adjust the security audit plugin to be relvent for the plugin. Not a whole site vulnerability scan.
- Look into adding an API scan feature for using WP Scan for clients without them needing to have the Securi plugin installed for the sake of security (why reivent the wheel)
- Look into making the QR code image in the connection tab for easier setup.
- Look into the type of message system we can use for realtime por near realtime? MQTT? Whatever we use should work on shared servers.
- Hashing the access token requires a user ID to be sent as well in the API. Is there any other way to do this effectivly.
- Fix time expired access tokens
- Add in an option for how long a token is valid for.
- Add hook for password reset and token removal.
- Look into issuing a new refresh token every so often in normal requests so that the refresh token revolves. This will require the any app using this to look for a new refreh token in just about every call.
- Pay model is support and security auditing?
- Pay model idea would be to start and configure a full server that supports voice, and realtime logic as well?
- Pay model support? Pro Plugin with license? Pro could have even more features. 
- Pay model - Simple donate form like RAR model. Ask nicely?

## License

This plugin is licensed under the GPLv2 or later.