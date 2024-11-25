# NelmioSecurityBundle

## About

The NelmioSecurityBundle provides additional security features for your Symfony application.

## Installation

Require the `nelmio/security-bundle` package in your composer.json and update your dependencies:
```bash
composer require nelmio/security-bundle
```

The bundle should be automatically enabled by [Symfony Flex][1]. If you don't use
Flex, you'll need to enable it manually as explained [in the docs][2].

## Features

Read [the docs][2] for the details and configuration needed for each feature:

* **Content Security Policy**: Cross site scripting attacks (XSS) can be mitigated
in modern browsers using a policy which instructs the browser never to execute inline scripts, or never to
load content from another domain than the page's domain.

* **Signed Cookies**: Specify certain cookies to be signed, so that the user cannot modify
  them. Note that they will not be encrypted, but signed only. The contents will still be
  visible to the user.

* **Clickjacking Protection**: X-Frame-Options header is added to all responses to prevent your
  site from being put in a frame/iframe. This can have serious security implications as it has
  been demonstrated time and time again with Facebook and others. You can allow framing of your
  site from itself or from anywhere on a per-URL basis.

* **External Redirects Detection**: Redirecting from your site to arbitrary URLs based on user
  input can be exploited to confuse users into clicking links that seemingly point to valid
  sites while they in fact lead to malicious content. It also may be possible to gain PageRank
  that way.

* **Forced HTTPS/SSL Handling**: This forces all requests to go through SSL. It will also
  send [HSTS](http://tools.ietf.org/html/draft-hodges-strict-transport-sec-02) headers so that
  modern browsers supporting it can make users use HTTPS even if they enter URLs without https,
  avoiding attacks on public Wi-Fi.

* **Flexible HTTPS/SSL Handling**: If you don't want to force all users to use HTTPS, you should
  at least use secure session cookies and force SSL for logged-in users. But then logged-in users
  appear logged-out when they access a non-HTTPS resource. This is not really a good solution.
  This will make the application detect logged-in users and redirect them to a secure URL,
  without making the session cookie insecure.

* **Disable Content Type Sniffing**: Require that scripts are loaded using the correct mime type.
  This disables the feature that some browsers have which uses content sniffing to determine if the response is a valid
  script file or not.

* (DEPRECATED) **XSS Protection**: Enables/Disables Microsoft XSS Protection on compatible browsers (IE 8 and newer).

* **Referrer Policy**: `Referrer-Policy` header is added to all responses to control the `Referer` header
  that is added to requests made from your site, and for navigations away from your site by browsers.

## Usage

See [the documentation][2] for usage instructions.

## License

Released under the MIT License, see LICENSE.

[1]: https://symfony.com/doc/current/setup/flex.html
[2]: https://symfony.com/bundles/NelmioSecurityBundle/
