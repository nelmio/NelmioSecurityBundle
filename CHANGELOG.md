### 2.0.1 (2016-07-13)
  * Fix CookieSessionHandler::open that should return true unless there's an error

### 2.0.0 (2016-05-17)
  * Add support for Content-Security-Policy Level 2 directives
  * Add support for Content-Security-Policy Level 2 signatures (nonce and message digest)
  * Add browser adaptive directives - do not send directives not supported by browser - via browser_adaptive parameter
  * Allow report-uri to be defined as a scalar
  * Deprecate encrypted cookie support du to high coupling to mcrypt deprecated extension
  * Drop backward-compatibility with first deprecated CSP configuration

### 1.10.0 (2016-02-23)

  * Added ability to restrict forced_ssl capability to some hostnames only
  * Fixed Symfony 3 compatibility

### 1.9.1 (2016-01-17)

  * BugFix: Fix LoggerInterface type hints to support PSR-3 loggers and not only Symfony 2.0 loggers

### 1.9.0 (2016-01-04)

  * Add Symfony 3 compatibility
  * external_redirects definition can now contains full URL
  * Allow dynamic CSP configuration
  * BugFix: Fix clickjacking URL normalization when containing dash and no underscore

### 1.8.0 (2015-09-12)

  * Added HTTP response's content-type restriction for Clickjacking and CSP headers.
  * Added Microsoft's XSS-Protection support
  * Disabled Clickjacking, CSP and NoSniff headers in the context of HTTP redirects
  * Fixed bug in handling of the external_redirects.log being disabled

### 1.7.0 (2015-05-10)

  * Added a `Nelmio\SecurityBundle\ExternalRedirect\TargetValidator` interface to implement custom rules for the external_redirects feature. You can override the `nelmio_security.external_redirect.target_validator` service to change the default.
  * Added a `hosts` key in the CSP configuration to restrict CSP-checks to some host names
  * Fixed a bug in `flexible_ssl` where the auth cookie was updated with a wrong expiration time the second time the visitor comes to the site.
  * Removed X-Webkit-CSP header as none of the webkits using it are still current.

### 1.6.0 (2015-02-01)

  * Added a `forced_ssl.hsts_preload` flag to allow adding the preload attribute on HSTS headers

### 1.5.0 (2015-01-01)

  * Added ability to have different configs for both reported and enforced CSP rules
  * Added support for ALLOW and ALLOW FROM syntaxes in the Clickjacking Protection
  * Added support for HHVM and PHP 5.6
  * Fixed enabling of cookie signing when the cookie list is empty

### 1.4.0 (2014-02-13)

  * Added default controller to log CSP violations
  * Added a flag to remove outdated non-standard CSP headers and only send the `Content-Security-Policy` one

### 1.3.0 (2014-01-08)

  * Added support for setting the X-Content-Type-Options header

### 1.2.0 (2013-07-29)

  * Added Content-Security-Policy (CSP) 1.0 support
  * Added forced_ssl.whitelist property to define URLs that do not need to be force-redirected
  * Fixed session loss bug on 404 URLs in the CookieSessionHandler

### 1.1.0 (2013-03-27)

  * Added a cookie session storage (use only if really needed, and combine it with `encrypted_cookie`)
  * Fixed error reporting if mcrypt is not enabled and you try to use encryption

### 1.0.0 (2013-01-08)

  * Initial release
