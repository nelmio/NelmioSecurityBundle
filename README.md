# NelmioSecurityBundle

## About

The NelmioSecurityBundle provides additional security features for your Symfony2 application.

## Installation

Require the `nelmio/security-bundle` package in your composer.json and update your dependencies.

    $ composer require nelmio/security-bundle

Add the NelmioSecurityBundle to your application's kernel:

```php
public function registerBundles()
{
    $bundles = array(
        ...
        new Nelmio\SecurityBundle\NelmioSecurityBundle(),
        ...
    );
    ...
}
```

## Features

* **[Content Security Policy](#content-security-policy)**: Cross site scripting attacks (XSS) can be mitigated
in modern browsers using a policy which instructs the browser never to execute inline scripts, or never to
load content from another domain than the page's domain.

* **[Signed Cookies](#signed-cookies)**: Specify certain cookies to be signed, so that the user cannot modify
  them. Note that they will not be encrypted, but signed only. The contents will still be
  visible to the user.

* **[Encrypted Cookies](#encrypted-cookies)**: Specify certain cookies to be encrypted, so that the value cannot be
  read. When you retrieve the cookie it will be automatically decrypted.

* **[Clickjacking Protection](#clickjacking-protection)**: X-Frame-Options header is added to all responses to prevent your
  site from being put in a frame/iframe. This can have serious security implications as it has
  been demonstrated time and time again with Facebook and others. You can allow framing of your
  site from itself or from anywhere on a per-URL basis.

* **[External Redirects Detection](#external-redirects-detection)**: Redirecting from your site to arbitrary URLs based on user
  input can be exploited to confuse users into clicking links that seemingly point to valid
  sites while they in fact lead to malicious content. It also may be possible to gain PageRank
  that way.

* **[Forced HTTPS/SSL Handling](#forced-httpsssl-handling)**: This forces by all requests to go through SSL. It will also
  send [HSTS](http://tools.ietf.org/html/draft-hodges-strict-transport-sec-02) headers so that
  modern browsers supporting it can make users use HTTPS even if they enter URLs without https,
  avoiding attacks on public Wi-Fi.

* **[Flexible HTTPS/SSL Handling](#flexible-httpsssl-handling)**: If you don't want to force all users to use HTTPS, you should
  at least use secure session cookies and force SSL for logged-in users. But then logged-in users
  appear logged-out when they access a non-HTTPS resource. This is not really a good solution.
  This will make the application detect logged-in users and redirect them to a secure URL,
  without making the session cookie insecure.

* **[Cookie Session Handler](#cookie-session-handler)**: You can configure the session handler to use a cookie based storage.
  **WARNING**: by default the session is not encrypted, it is your responsibility to properly configure the Encrypted Cookies
  section to include the session cookie (default name: session). The size limit of a cookie is 4KB, so make sure you are not
  storing object or long text into session.

* **[Disable Content Type Sniffing](#content-type-sniffing)**: Require that scripts are loaded using the correct mime type.
  This disables the feature that some browsers have which uses content sniffing to determine if the response is a valid
  script file or not.

* **[XSS Protection](#xss-protection)**: Enables/Disables Microsoft XSS Protection on compatible browsers (IE 8 and newer).

## Maximum Security Configuration (Read on for detailed recommendations!)

```yaml
nelmio_security:
    # signs/verifies all cookies
    signed_cookie:
        names: ['*']
    # encrypt all cookies
    encrypted_cookie:
        names: ['*']
    # prevents framing of the entire site
    clickjacking:
        paths:
            '^/.*': DENY
    # prevents redirections outside the website's domain
    external_redirects:
        abort: true
        log: true

    # prevents inline scripts, unsafe eval, external scripts/images/styles/frames, etc
    csp:
        report:
            report-uri: [/nelmio/csp/report]
            default-src: [ 'self' ]
            # There's no flash on our site
            object-src:
                - 'none'
            script-src:
                - 'unsafe-inline'
                - 'unsafe-eval'
                - 'self'
            hosts: []
            content_types: []
        enforce:
            # see https://github.com/nelmio/NelmioSecurityBundle/issues/32
            report-uri: [/nelmio/csp/report]
            script-src:
                - 'self'

    # disables content type sniffing for script resources
    content_type:
        nosniff: true

    # Forces Microsoft's XSS-Protection with
    # its block mode
    xss_protection:
        enabled: true
        mode_block: true

    # forced HTTPS handling, don't combine with flexible mode
    # and make sure you have SSL working on your site before enabling this
#    forced_ssl:
#        hsts_max_age: 2592000 # 30 days
#        hsts_subdomains: true

    # flexible HTTPS handling, read the detailed config info
    # and make sure you have SSL working on your site before enabling this
#    flexible_ssl:
#        cookie_name: auth
#        unsecured_logout: false
```

## Configuration Detail

### Content Security Policy:

Using CSP you can set a policy which modern browsers understand and will honor. The policy contains nine different
directives; `default-src`, `script-src`, `object-src`, `style-src`, `img-src`, `media-src`, `frame-src`,
`font-src`, `connect-src`, `report-uri`. You can provide an array of directives per content type. Empty content
types will inherit from `default-src`, specified content types will never inherit from `default-src`. Please see
the [Content Security Policy 1.0](http://www.w3.org/TR/CSP) specification for details.

Each directive should be a domain, URI or keyword. The keyword `'self'` will allow content from the same origin as
the page. If you need to allow inline scripts or `eval()` you can use `'unsafe-inline'` and `'unsafe-eval'`.

**WARNING:** By using `'unsafe-inline'` or `'unsafe-eval'` you're effectively disabling the XSS protection
mechanism of CSP.

Apart from content types, the policy also accepts `report-uri` which should be a URI where a browser can POST a
[JSON payload](https://developer.mozilla.org/en-US/docs/Security/CSP/Using_CSP_violation_reports#Sample_violation_report)
to whenever a policy directive is violated.

An optional `content_types` key lets you restrict the Content Security Policy headers only on some HTTP 
response given their content type.

Finally, an optional `hosts` key lets you configure which hostnames (e.g. `foo.example.org`)
the CSP rule should be enforced on. If the list is empty (it is by default), all
hostnames will use the CSP rule.

```yaml
nelmio_security:
    csp:
        report_logger_service: logger
        enforce:
            report-uri: /nelmio/csp/report
            default-src: [ 'self' ]
            frame-src: [ 'https://www.youtube.com' ]
            script-src:
                - 'self'
                - 'unsafe-inline'
            img-src:
                - 'self'
                - facebook.com
                - flickr.com
            hosts: []
            content_types: []
        report:
            report-uri: /nelmio/csp/report
            script-src:
                - 'self'
```

The above configuration would enforce the following policy:

* Default is to allow from same origin as the page
* Frames only from secure youtube connections
* JavaScript from same origin and from inline `<script>` tags
* Images from same origin, `facebook.com` and `flickr.com`

Any violation of the enforced policy would be posted to /nelmio/csp/report.

In addition, the configuration only reports but doesn't enforce the policy that JavaScript may only be executed
when it comes from the same server.

The bundle provides a default reporting implementation that logs violations as notices
to the default logger, to enable add the following to your routing.yml:

```yaml
nelmio_security:
    path:     /nelmio/csp/report
    defaults: { _controller: nelmio_security.csp_reporter_controller:indexAction }
    methods:  [POST]
```

(Optional) Use *report_logger_service* to log to the 'security' channel:

```yaml
nelmio_security:
    csp:
        report_logger_service: monolog.logger.security
```

(Optional) Disable *compat_headers* to avoid sending X-Content-Security-Policy
(IE10, IE11, Firefox < 23). This will mean those browsers get no CSP instructions.

```yaml
nelmio_security:
    csp:
        compat_headers: false
```

### **Signed Cookies**:

Ideally you should explicitly specify which cookies to sign. The reason for this is simple.
Cookies are sent with each request. Signatures are often longer than the cookie values themselves,
so signing everything would just needlessly slow down your app and increase bandwidth usage for
your users.

```yaml
nelmio_security:
    signed_cookie:
        names: [test1, test2]
```

However, for simplicity reasons, and to start with a high security and optimize later, you can
specify '*' as a cookie name to have all cookies signed automatically.

```
nelmio_security:
    signed_cookie:
        names: ['*']
```

Additional, optional configuration settings:

```yaml
nelmio_security:
    signed_cookie:
        secret: this_is_very_secret # defaults to global %secret% parameter
        hash_algo: sha512 # defaults to sha256, see `hash_algos()` for available algorithms
```

### **Encrypted Cookies**:

Encrypts the cookie values using `nelmio_security.encrypted_cookie.secret`. It works the same as
Signed Cookies:

```yaml
nelmio_security:
    encrypted_cookie:
        names: [test1, test2]
```

Additional, optional configuration settings:

```yaml
nelmio_security:
    encrypted_cookie:
        secret: this_is_very_secret # defaults to global %secret% parameter
        algorithm: rijndael-256 # defaults to rijndael-128, see `mcrypt_list_algorithms()` for available algorithms
```

### **Clickjacking Protection**:

Most websites do not use frames and do not need to be frame-able. This is a common attack vector
for which all current browsers (IE8+, Opera10.5+, Safari4+, Chrome4+ and Firefox3.7+) have a
solution. An extra header sent by your site will tell the browser that it can not be displayed in
a frame. Browsers react by showing a short explanation instead of the content, or a blank page.

The valid values for the `X-Frame-Options` header are `DENY` (prevent framing from all pages) and
`SAMEORIGIN` (prevent framing from all pages not on the same domain). Additionally this bundle
supports the `ALLOW` option which skips the creation of the header for the matched URLs, if you
want to whitelist a few URLs and then DENY everything else.

One more option, as of yet [not well supported](https://developer.mozilla.org/en-US/docs/Web/HTTP/X-Frame-Options),
is to use `ALLOW FROM uri` where `uri` can be any origin URL, from
`example.org` to `https://example.org:123/sub/path`. This lets you specify
exactly which domain can embed your site, in case you have a multi-domain setup.

Default configuration (deny everything):

```yaml
nelmio_security:
    clickjacking:
        paths:
            '^/.*': DENY
        content_types: []
```

Whitelist configuration (deny all but a few URLs):

```yaml
nelmio_security:
    clickjacking:
        paths:
            '^/iframes/': ALLOW
            '^/business/': 'ALLOW FROM https://biz.example.org'
            '^/local/': SAMEORIGIN
            '^/.*': DENY
        content_types: []
```

You can also of course only deny a few critical URLs, while leaving the rest alone:

```yaml
nelmio_security:
    clickjacking:
        paths:
            '^/message/write': DENY
        content_types: []
```

An optional `content_types` key lets you restrict the X-Frame-Options header only on some HTTP 
response given their content type.

### **External Redirects Detection**:

This feature helps you detect and prevent redirects to external sites. This can easily happen
by accident if you carelessly take query parameters as redirection target.

You can log those (it's logged at warning level) by turning on logging:

```yaml
nelmio_security:
    external_redirects:
        log: true
```

You can abort (they are replaced by a 403 response) the redirects:

```yaml
nelmio_security:
    external_redirects:
        abort: true
```

Or you can override them, replacing the redirect's `Location` header by a route name or
another URL:

```yaml
# redirect to the 'home' route
nelmio_security:
    external_redirects:
        override: home

# redirect to another URL
nelmio_security:
    external_redirects:
        override: /foo
```

If you want to display the URL that was blocked on the overriding page you can
specify the `forward_as` parameter, which defines which query parameter will
receive the URL. For example using the config below, doing a redirect to
`http://example.org/` will be overridden to `/external-redirect?redirUrl=http://example.org/`.

```yaml
# redirect and forward the overridden URL
nelmio_security:
    external_redirects:
        override: /external-redirect
        forward_as: redirUrl
```

Since it's quite common to have to redirect outside the website for legit reasons,
typically OAuth logins and such, you can whitelist a few domain names. All their subdomains
will be whitelisted as well, so that allows you to whitelist your own website's subdomains
if needed.

```yaml
nelmio_security:
    external_redirects:
        abort: true
        whitelist:
            - twitter.com
            - facebook.com
```

### **Forced HTTPS/SSL Handling**:

By default, this option forces your entire site to use SSL, always. It redirect all users
reaching the site with a http:// URL to a https:// URL.

The base configuration for this is the following:

```yaml
nelmio_security:
    forced_ssl: ~
```

If you turn this option on, it's recommended to also set your session cookie to be secure,
and all other cookies your send for that matter. You can do the former using:

```yaml
framework:
    session:
        cookie_secure: true
```

To keep a few URLs from being force-redirected to SSL you can define a whitelist of regular
expressions:

```yaml
nelmio_security:
    forced_ssl:
        enabled: true
        whitelist:
            - ^/unsecure/
```

Then if you want to push it further, you can enable
[HTTP Strict Transport Security (HSTS)](http://tools.ietf.org/html/draft-hodges-strict-transport-sec-02).
This is basically sending a header to tell the browser that your site must always be
accessed using SSL. If a user enters a http:// URL, the browser will convert it to https://
automatically, and will do so before making any request, which prevents man-in-the-middle
attacks.

The browser will cache the value for as long as the specified `hsts_max_age` (in seconds), and if
you turn on the `hsts_subdomains` option, the behavior will be applied to all subdomains as well.

```yaml
nelmio_security:
    forced_ssl:
        hsts_max_age: 2592000 # 30 days
        hsts_subdomains: true
```

You can also tell the browser to add your site to the list of known HSTS sites, by enabling
`hsts_preload`. Once your site has appeared in the Chrome and Firefox preload lists, then new
users who come to your site will already be redirected to https urls.

```yaml
nelmio_security:
    forced_ssl:
        hsts_max_age: 10886400 # 18 weeks
        hsts_preload: true
```

> **Note:** A value of at least 18 weeks is currently required by [Chrome](https://hstspreload.appspot.com)
> and [Firefox](https://blog.mozilla.org/security/2012/11/01/preloading-hsts/). It seems
> `hsts_subdomains` must also be enabled for preloading to work.

You can speed up the inclusion process by submitting your site to the [HSTS Preload List](https://hstspreload.appspot.com).

A small word of caution: While HSTS is great for security, it means that if the browser
can not establish your SSL certificate is valid, it will not allow the user to query your site.
That just means you should be careful and renew your certificate in due time.

Note: HSTS presently (Jan. 2015) works in Firefox 4+, Chrome 4+ and Opera 12+.
      Check [caniuse](http://caniuse.com/#feat=stricttransportsecurity) for HSTS support in other browsers.
      
### **Flexible HTTPS/SSL Handling**:

The best way to handle SSL securely is to enable it for your entire site.

However in some cases this is not desirable, be it for caching or performance reasons,
or simply because most visitors of your site are anonymous and don't benefit much from the
added privacy and security of SSL.

If you don't want to enable SSL across the board, you need to avoid that people on insecure
networks (typically open Wi-Fi) get their session cookie stolen by sending it non-encrypted.
The way to achieve this is to set your session cookie to be secure as such - but don't do
it just yet, keep reading to the end.

```yaml
framework:
    session:
        cookie_secure: true
```

If you use the remember-me functionality, you would also mark that one as secure:

```yaml
security:
    firewalls:
        somename:
            remember_me:
                secure: true
```

Now if you do this, you have two problems. First, insecure pages will not be able to use
the session anymore, which can be inconvenient. Second, if a logged in user gets to a
non-https page of your site, it is seen as anonymous since his browser will not send the
session cookie. To fix this, this bundle sets a new insecure cookie
(`flexible_ssl.cookie_name`, defaults to `auth`) once a user logs in. That way, if any page
is accessed insecurely by a logged in user, he is redirected to the secure version of the
page, and his session is then visible to the framework.

Enabling the `flexible_ssl` option of the NelmioSecurityBundle will make sure that
logged-in users are always seeing secure pages, and it will make sure their session cookie
is secure, but anonymous users will still be able to have an insecure session, if you need
to use it to store non critical data like language settings and whatnot. The remember-me
cookie will also be made always secure, even if you leave the setting to false.

```yaml
nelmio_security:
    flexible_ssl:
        cookie_name: auth
        unsecured_logout: false
```

You have to configure one more thing in your security configuration though, every firewall
should have our logout listener added, so that the special `auth` cookie can be cleared when
users log out. You can do it as such:

```yaml
security:
    firewalls:
        somename:
            # ...
            logout:
                handlers:
                    - nelmio_security.flexible_ssl_listener
```

On logout, if you would like users to be redirected to an unsecure page set ``unsecured_logout``
to true.

### Cookie Session Handler:

You can configure the session handler to use a cookie based storage. There are various reasons to do this, but generally speaking unless you have a very good one [you should avoid it](http://wonko.com/post/why-you-probably-shouldnt-use-cookies-to-store-session-data).

**WARNING**: by default the session is not encrypted, it is your responsibility to properly
configure the Encrypted Cookies section to include the session cookie (default name: session).
The size limit of a cookie is 4KB, so make sure you are not storing objects or long
strings in the session.

```yaml
framework:
    session:
        handler_id: nelmio_security.session.handler

nelmio_security:
    cookie_session:
        enabled: true
        name: session

    encrypted_cookie:
        names: [session]
```

### Content Type Sniffing

Disables the content type sniffing for script resources. Forces the browser to only execute script files with valid
content type headers. This is a non-standard header from Microsoft, more information can be found in
[their documentation at MSDN](http://msdn.microsoft.com/en-us/library/ie/gg622941.aspx).

```yaml
nelmio_security:
    content_type:
        nosniff: true
```

### XSS Protection

Enables or disables Microsoft XSS Protection on compatible browsers. 
This is a non-standard header from Microsoft, more information can be found in
[their documentation at MSDN](http://blogs.msdn.com/b/ieinternals/archive/2011/01/31/controlling-the-internet-explorer-xss-filter-with-the-x-xss-protection-http-header.aspx).

```yaml
nelmio_security:
    xss_protection:
        enabled: true
        mode_block: true
```

## License

Released under the MIT License, see LICENSE.
