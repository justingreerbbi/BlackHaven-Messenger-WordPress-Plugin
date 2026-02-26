# BlackHaven Messenger

BlackHaven Messenger is a WordPress plugin that adds private messaging functionality to a BlackHaven-powered site. It is designed for secure communication, a straightforward user experience, and an architecture that can grow over time.

## Overview

This plugin provides messaging features for WordPress sites that want a self-hosted communication system. It includes support for direct messaging, notifications, and a client-side encryption model intended to reduce server-side exposure to message contents.

## Features

- Real-time or near real-time messaging between users
- User-friendly interface for sending and receiving messages
- Notification support for new activity
- Client-side encryption before message data reaches the server
- Architecture designed with privacy and future scalability in mind

## Requirements

- WordPress 6.8 or higher
- PHP 8.2 or higher

## Installation

1. Download or clone this repository.
2. Upload the plugin to your WordPress `/wp-content/plugins/` directory.
3. Activate the plugin from the WordPress admin dashboard.
4. Open the BlackHaven Messenger settings area and configure the plugin for your site.

## Usage

After activation:

1. Go to the Messenger section in the WordPress admin dashboard.
2. Review and configure the available settings.
3. Enable messaging for your site users.
4. Start conversations through the supported interface or client application.

## Security Notes

BlackHaven Messenger is built with privacy-focused design choices. Message content is encrypted on the client before it is processed by the server. The server may store encrypted conversation data, but it is not intended to store plaintext message content.

The project also favors reducing unnecessary exposure of sensitive data through URL parameters, logs, caches, and browser history.

## Frequently Asked Questions

### Why do the API routes use POST?

The plugin favors privacy and security over strict REST-style purity. GET requests can expose data through server logs, browser history, proxies, caches, analytics tools, and other systems. Using POST helps reduce that exposure.

### Why is the user ID included in requests if an access token is already provided?

Access tokens are stored in hashed form. Including the user ID allows faster and more efficient lookup of the hashed token during request validation.

### Are conversations stored on the server, and are they encrypted?

Yes, conversation data can be stored on the server. However, message content is encrypted on the client before it reaches the server.

### Is the encryption post-quantum secure?

Not at this time. The current implementation uses strong encryption, but it is not yet post-quantum resilient. Post-quantum approaches are being evaluated for future versions.

### When a message is deleted, is it removed for all participants?

Yes. When a message or conversation is deleted, it is removed for all participants and deleted from the server as part of the intended behavior.

## Development Priorities

The following items are planned or under consideration:

- Move user identifiers out of URL paths and into request bodies to reduce exposure in logs
- Replace any remaining parameterized URL patterns with POST body parameters where appropriate
- Avoid exposing direct internal user identifiers when possible
- Continue refactoring routes to prefer POST over GET when privacy is a concern
- Document the security and privacy reasoning behind these API design decisions
- Add PreKey support for improved forward secrecy
- Evaluate a double ratchet design for future message key management
- Add database and application logic required for symmetric key exchange improvements
- Review whether consolidating API access behind a more limited endpoint surface would improve privacy and reduce exposure

## Contributing

Pull requests are welcome. For major changes, please open an issue first so the proposed change can be discussed before implementation.

## License

This project is licensed under the MIT License.
