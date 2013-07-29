### 1.2.0 (2013-07-29)

  * Added Content-Security-Policy (CSP) 1.0 support
  * Added forced_ssl.whitelist property to define URLs that do not need to be force-redirected
  * Fixed session loss bug on 404 URLs in the CookieSessionHandler

### 1.1.0 (2013-03-27)

  * Added a cookie session storage (use only if really needed, and combine it with `encrypted_cookie`)
  * Fixed error reporting if mcrypt is not enabled and you try to use encryption

### 1.0.0 (2013-01-08)

  * Initial release
