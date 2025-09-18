# BlackHaven Messenger

A WordPress plugin that adds messaging functionality to your BlackHaven site.

## Features

-   Real-time messaging between users
-   User-friendly interface
-   Notification support
-   Secure and scalable

## Installation

1. Download or clone the repository.
2. Upload the plugin to your WordPress `/wp-content/plugins/` directory.
3. Activate the plugin from the WordPress admin dashboard.

## Usage

-   Navigate to the Messenger section in your WordPress dashboard.
-   Configure settings as needed.
-   Start messaging with other users.

## Requirements

-   WordPress 5.0+
-   PHP 7.4+

## Frequently Asked Question

Q. Why do all API routes use POST?
A. Security and Privacy over purity is the goal. GET requests often leak data in the server logs, caching, browser history, analytics, etc.

Q. Why us the user ID needed in all requests if an access token is already used?
A. The plugin stores access token in hash form. Sending the user ID provides faster lookups to lookup hashed tokens.

Q. Are conversations stored on the server and if so, are they encrypted?
A. Yes, conversations are indeed store on the system, however they are encrypted on the clients before they are seen by the server.

Q. Is the encryption used Post-Quantum Computing resilient?
A. As of now, no. While the clients use crazy strong encryption, it is not ready for PQC. We are exploring options to implement PQC safe encryption.

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## ToDos

-   Using the user ID in the URL is not secure, move this to the body parameters to halp with log leaks.
-   While traditional API routes may use /x/y/x for parameters passing during a request, this need to be changed. URLs are logged in servers.
-   Real ID's for users should nt be used? This can provide a work around with other weaknesses in the WordPress platform.
-   Refactor all requests to use POST instead of GET. privacy overrides purity in this case. Do a write up on why these things are being modified.
-   Add PreKey support for forward security. Double ratchet preferred. I 100% forgot about this until I was writing the mobile API class. New DB table, and logic for symmetric key gen and exchange.

## License

This project is licensed under the MIT License.
