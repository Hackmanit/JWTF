[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

# JSON Web Token Forgery (JWTF)
JWTF has two main purposes:
1. Allow to manually decode, analyze, and alter JSON Web Tokens (JWTs).
2. Automatically generate manipulated JWTs to be used in penetration tests, security audits, bug bounty hunting, and CTFs.

JWTF was developed by [Hackmanit](https://hackmanit.de) and [Niklas Conrad](https://www.github.com/conni404) as a part of his bachelor's thesis in collaboration with the [Chair for Network and Data Security](https://github.com/RUB-NDS/), Ruhr University Bochum.

JWTF supports all well-known attacks against the validation of JWTs and automatically applies these attack vectors to a given JWT. As an output it generates a text file with all manipulated tokens. This text file can then be used in semi-automated tests, for example using the "Intruder" feature of [Burp Suite](https://portswigger.net/burp/pro).

This eases the process of testing an implementation for vulnerabilities in its JWT validation logic.

- [Features](#features)
- [How to Use JWTF](#how-to-use-jwtf)
- [How to Use This Repository](#how-to-use-this-repository)
- [Background Information](#background-information)
- [License](#license)

## Features
- Decode/Encode JWTs
- Sign/Verify JWTs
- Beautify/Minify JSON in the token's header and body
- Support for invalid JSON in the token's header or body
- Apply _all*_ well-known attacks against JWTs to a given JWT
- Encrypt/Decrypt JSON Web Encryption (JWE)
- Generate keys for signing JWTs
- Convert PEM to JWK and vice versa
- Support for all signature algorithms specified in [RFC 7518](https://datatracker.ietf.org/doc/html/rfc7518#section-3)
- Support for (almost) all encryption algorithms specified in [RFC 7518](https://datatracker.ietf.org/doc/html/rfc7518)

_More information will follow soon._

_*as of 2025-08-14_
## How to Use JWTF?
_More information will follow soon._

## How to Use This Repository
Simply access https://jwt.wtf/ to use JWTF.
There is no need to download this repository unless you want to contribute in the development of JWTF or want to use JWTF locally.

## Background Information
A blog post providing more information about JWTF will be released in the future here:

[Cyber Security Blog - Hackmanit](https://hackmanit.de/en/blog-en/)

JWTF was developed as a part of a bachelor's thesis by [Niklas Conrad](https://www.github.com/conni404) in collaboration with the [Chair for Network and Data Security](https://github.com/RUB-NDS/) (Ruhr University Bochum).
You can find results of the bachelor's thesis publicly available here:
- _Soon:_ Bachelor's Thesis (PDF)

## License
JSON Web Token Forgery (JWTF) was developed by [Hackmanit](https://hackmanit.de) and [Niklas Conrad](https://www.github.com/conni404) as a part of his bachelor's thesis in collaboration with the [Chair for Network and Data Security](https://github.com/RUB-NDS/), Ruhr University Bochum. JWTF is licensed under the [Apache License, Version 2.0](license.txt).

<a href="https://hackmanit.de"><img src="https://www.hackmanit.de/templates/hackmanit-v2/img/wbm_hackmanit.png" width="30%"></a>
