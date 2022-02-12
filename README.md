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

* **[Clickjacking Protection](#clickjacking-protection)**: X-Frame-Options header is added to all responses to prevent your
  site from being put in a frame/iframe. This can have serious security implications as it has
  been demonstrated time and time again with Facebook and others. You can allow framing of your
  site from itself or from anywhere on a per-URL basis.

* **[External Redirects Detection](#external-redirects-detection)**: Redirecting from your site to arbitrary URLs based on user
  input can be exploited to confuse users into clicking links that seemingly point to valid
  sites while they in fact lead to malicious content. It also may be possible to gain PageRank
  that way.

* **[Forced HTTPS/SSL Handling](#forced-httpsssl-handling)**: This forces all requests to go through SSL. It will also
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
  storing objects or long text into session.

* **[Disable Content Type Sniffing](#content-type-sniffing)**: Require that scripts are loaded using the correct mime type.
  This disables the feature that some browsers have which uses content sniffing to determine if the response is a valid
  script file or not.

* **[XSS Protection](#xss-protection)**: Enables/Disables Microsoft XSS Protection on compatible browsers (IE 8 and newer).

* **[Referrer Policy](#referrer-policy)**: `Referrer-Policy` header is added to all responses to control the `Referer` header
  that is added to requests made from your site, and for navigations away from your site by browsers.

**WARNING**: The following features are now deprecated:

* **[Encrypted Cookies](#encrypted-cookies)**: Specify certain cookies to be encrypted, so that the value cannot be
  read. When you retrieve the cookie it will be automatically decrypted.

## Maximum Security Configuration (Read on for detailed recommendations!)

```yaml
nelmio_security:
    # signs/verifies all cookies
    signed_cookie:
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
        hosts: []
        content_types: []
        enforce:
            level1_fallback: false
            browser_adaptive:
                enabled: false
            report-uri: %router.request_context.base_url%/nelmio/csp/report
            default-src:
                - 'none'
            script-src:
                - 'self'
            block-all-mixed-content: true # defaults to false, blocks HTTP content over HTTPS transport
            # upgrade-insecure-requests: true # defaults to false, upgrades HTTP requests to HTTPS transport

    # disables content type sniffing for script resources
    content_type:
        nosniff: true

    # forces Microsoft's XSS-Protection with
    # its block mode
    xss_protection:
        enabled: true
        mode_block: true
        report_uri: %router.request_context.base_url%/nelmio/xss/report

    # Send a full URL in the `Referer` header when performing a same-origin request,
    # only send the origin of the document to secure destination (HTTPS->HTTPS),
    # and send no header to a less secure destination (HTTPS->HTTP).
    # If `strict-origin-when-cross-origin` is not supported, use `no-referrer` policy,
    # no referrer information is sent along with requests.
    referrer_policy:
        enabled: true
        policies:
            - 'no-referrer'
            - 'strict-origin-when-cross-origin'

    # forces HTTPS handling, don't combine with flexible mode
    # and make sure you have SSL working on your site before enabling this
#    forced_ssl:
#        hsts_max_age: 2592000 # 30 days
#        hsts_subdomains: true
#        redirect_status_code: 302 # default, switch to 301 for permanent redirects

    # flexible HTTPS handling, read the detailed config info
    # and make sure you have SSL working on your site before enabling this
#    flexible_ssl:
#        cookie_name: auth
#        unsecured_logout: false
```

## Configuration Detail

### Content Security Policy:

Using CSP you can set a policy which modern browsers understand and will honor. The policy contains many different
directives; `default-src`, `script-src`, `object-src`, `style-src`, `img-src`, `media-src`, `frame-src`,
`font-src`, `connect-src`, `base-uri`, `child-src`, `form-action`, `frame-ancestors`, `plugin-types`,
`block-all-mixed-content`, `upgrade-insecure-requests`, `report-uri`, `manifest-src`.

You can provide an array of directives per content type, except for `block-all-mixed-content` and
`upgrade-insecure-requests` that only accept boolean values. Empty content
types will inherit from `default-src`, specified content types will never inherit from `default-src`. Please see
the [Content Security Policy 1.0](https://www.w3.org/TR/2012/CR-CSP-20121115/) and
[Content Security Policy 2.0](https://www.w3.org/TR/2015/CR-CSP2-20150721/) specifications for details.

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
        enabled: true
        report_logger_service: logger
        hosts: []
        content_types: []
        enforce:
            # see full description below
            level1_fallback: true
            # only send directives supported by the browser, defaults to false
            # this is a port of https://github.com/twitter/secureheaders/blob/83a564a235c8be1a8a3901373dbc769da32f6ed7/lib/secure_headers/headers/policy_management.rb#L97
            browser_adaptive:
                enabled: false
            report-uri: %router.request_context.base_url%/nelmio/csp/report
            default-src: [ 'self' ]
            frame-src: [ 'https://www.youtube.com' ]
            script-src:
                - 'self'
                - 'unsafe-inline'
            img-src:
                - 'self'
                - facebook.com
                - flickr.com
            block-all-mixed-content: true # defaults to false, blocks HTTP content over HTTPS transport
            # upgrade-insecure-requests: true # defaults to false, upgrades HTTP requests to HTTPS transport
        report:
            # see full description below
            level1_fallback: true
            # only send directives supported by the browser, defaults to false
            # this is a port of https://github.com/twitter/secureheaders/blob/83a564a235c8be1a8a3901373dbc769da32f6ed7/lib/secure_headers/headers/policy_management.rb#L97
            browser_adaptive:
                enabled: true
            report-uri: %router.request_context.base_url%/nelmio/csp/report
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

#### Using browser adaptive directives

The NelmioSecurityBundle can be configured to only send directives that can be understood by the browser. This reduces noise provided via the report URI.
This is a direct port of what has been done in [Twitter SecureHeaders library](https://github.com/twitter/secureheaders).

Use the `enabled` key to enable it.

```yaml
nelmio_security:
    csp:
        enforce:
            browser_adaptive:
                enabled: true
```

**WARNING** This will parse the user agent and can consume some CPU usage. You can specify a cached parser to
avoid consuming too much CPU:

```yaml
nelmio_security:
    csp:
        enforce:
            browser_adaptive:
                enabled: true
                parser: my_own_parser
```

And declare service `my_own_parser` based on one of the cached parser NelmioSecurityBundle provides or your own one.
For instance, using the `DoctrineCacheUAFamilyParser`:

```xml
    <service id="my_own_parser" class="Nelmio\SecurityBundle\UserAgent\UAFamilyParser\DoctrineCacheUAFamilyParser">
      <argument type="service" id="doctrine_cache.providers.redis_cache"/>
      <argument type="service" id="nelmio_security.ua_parser.ua_php"/>
      <argument>604800</argument>
    </service>
```

Have a look in the `Nelmio\SecurityBundle\UserAgent\UAFamilyParser` for these parsers.

#### Message digest for inline script handling

If you want to disable `'unsafe-inline'` on `script-src` or `style-src` (recommended), Nelmio Security Bundle
comes out of the box with message digest functionality. Twig is natively supported.

You can configure the algorithm used for message digest in the configuration.

```yaml
nelmio_security:
    csp:
        hash:
            algorithm: sha512 # default is sha256, available are sha256, sha384 and sha512
        enforce:
            # Provides compatibility with CSP level 1 (old / non-yet-compatible browsers) when using CSP level 2
            # features likes hash and nonce. It adds a 'unsafe-inline' source to a directive whenever a nonce or hash
            # is used.
            # From RFC: " If 'unsafe-inline' is not in the list of allowed style sources, or if at least one
            #             nonce-source or hash-source is present in the list of allowed style sources "
            # See https://www.w3.org/TR/CSP2/#directive-style-src and https://www.w3.org/TR/CSP2/#directive-script-src
            level1_fallback: true
            default-src: ['self']
```

In your Twig template use the `cspscript` and `cspstyle` tags to automatically compute the message digest and insert
it in your headers.

```twig
{% cspscript %}
<script>
    window.api_key = '{{ api_key }}';
</script>
{% endcspscript %}

// ...

{% cspstyle %}
<style>
    body {
        background-color: '{{ bgColor }}';
    }
</style>
{% endcspstyle %}
```

If you're not using Twig, you can use message digest with the `ContentSecurityPolicyListener`, it will automatically
compute the message digest and add it to the response CSP header:

```php

$listener->addScript("<script>
    window.api_key = '{{ api_key }}';
</script>");


$listener->addStyle("<style>
    body {
        background-color: '{{ bgColor }}';
    }
</style>");

```

#### Nonce for inline script handling

Content-Security-Policy specification also proposes a nonce implementation for inlining. Nelmio Security Bundle
comes out of the box with nonce functionality. Twig is natively supported.


In your Twig template use the `csp_nonce` function to access the nonce for the current request and add it to the response
CSP header. If you do not request a nonce, nonce will not be generated.

```twig
<script nonce="{{ csp_nonce('script') }}">
    window.api_key = '{{ api_key }}';
</script>

// ...

<style nonce="{{ csp_nonce('style') }}">
    body {
        background-color: '{{ bgColor }}';
    }
</style>
```

If you're not using Twig, you can use nonce functionality with the `ContentSecurityPolicyListener`:

```php
// generates a nonce at first time, returns the same nonce once generated
$listener->getNonce('script');
// or
$listener->getNonce('style');
```

#### Reporting:

Using the `report-uri` you can easily collect violation using the `ContentSecurityPolicyController`.
Here's an configuration example using `routing.yml`:

```yaml
csp_report:
    path: /csp/report
    methods: [POST]
    defaults: { _controller: nelmio_security.csp_reporter_controller::indexAction }
```

This part of the configuration helps to filter noise collected by this endpoint:

```yaml
nelmio_security:
    csp:
        report_endpoint:
            log_level: "notice" # Use the appropriate log_level
            log_formatter: ~    # Declare a service name that must implement Nelmio\SecurityBundle\ContentSecurityPolicy\Violation\Log\LogFormatterInterface
            log_channel: ~      # Declare the channel to use with the logger
            filters:
                # Filter false positive reports given a domain list
                domains: true
                # Filter false positive reports given a scheme list
                schemes: true
                # Filter false positive reports given known browser bugs
                browser_bugs: true
                # Filter false positive reports given known injected scripts
                injected_scripts: true
                # You can add you custom filter rules by implementing Nelmio\SecurityBundle\ContentSecurityPolicy\Violation\Filter\NoiseDetectorInterface
                # and tag the service with "nelmio_security.csp_report_filter"
            dismiss:
                # A list of key-values that should be dismissed
                # A key is either a domain or a regular expression
                # A value is a source or an array of source. The '*' wilcard is accepted
                '/^data:/': 'script-src'
                '/^https?:\/\/\d+\.\d+\.\d+\.\d+(:\d+)*/': '*'
                'maxcdn.bootstrapcdn.com': '*'
                'www.gstatic.com': ['media-src', 'img-src']
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

```yaml
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

**WARNING**: this service is now deprecated due to high coupling with deprecated mcrypt extension.

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
want to allow a few URLs and then DENY everything else.

One more option, as of yet [not well supported](https://developer.mozilla.org/en-US/docs/Web/HTTP/X-Frame-Options),
is to use `ALLOW-FROM uri` where `uri` can be any origin URL, from
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

Allow list configuration (deny all but a few URLs):

```yaml
nelmio_security:
    clickjacking:
        paths:
            '^/iframes/': ALLOW
            '^/business/': 'ALLOW-FROM https://biz.example.org'
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
typically OAuth logins and such, you can allow a few domain names. All their subdomains
will be allowed as well, so you can allow your own website's subdomains
if needed.

```yaml
nelmio_security:
    external_redirects:
        abort: true
        allow_list:
            - twitter.com
            - facebook.com
```

### **Forced HTTPS/SSL Handling**:

By default, this option forces your entire site to use SSL, always. It redirect all users
reaching the site with a http:// URL to a https:// URL with a 302 response.

The base configuration for this is the following:

```yaml
nelmio_security:
    forced_ssl: ~
```

If you turn this option on, it's recommended to also set your session cookie to be secure,
and all other cookies you send for that matter. You can do the former using:

```yaml
framework:
    session:
        cookie_secure: true
```

To keep a few URLs from being force-redirected to SSL you can define an allowed list of regular
expressions:

```yaml
nelmio_security:
    forced_ssl:
        enabled: true
        allow_list:
            - ^/unsecure/
```

To restrict the force-redirects to some hostnames only you can define a list of hostnames
as regular expressions:

```yaml
nelmio_security:
    forced_ssl:
        enabled: true
        hosts:
            - ^\.example\.org$
```

To change the way the redirect is done to a permanent redirect for example, you can set:

```yaml
nelmio_security:
    forced_ssl:
        enabled: true
        redirect_status_code: 301
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
users who come to your site will already be redirected to HTTPS URLs.

```yaml
nelmio_security:
    forced_ssl:
        hsts_max_age: 31536000 # 1 year
        hsts_preload: true
```

> **Note:** A value of at least 1 year is currently required by [Chrome](https://hstspreload.org/)
> and [Firefox](https://blog.mozilla.org/security/2012/11/01/preloading-hsts/).
> `hsts_subdomains` must also be enabled for preloading to work.

You can speed up the inclusion process by submitting your site to the [HSTS Preload List](https://hstspreload.org/).

A small word of caution: While HSTS is great for security, it means that if the browser
can not establish your SSL certificate is valid, it will not allow the user to query your site.
That just means you should be careful and renew your certificate in due time.

Note: HSTS presently (Feb. 2018) works in Firefox 4+, Chrome 4+, Opera 12+, IE 11+, Edge 12+ and Safari 7+.
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
non-HTTPS page of your site, it is seen as anonymous since his browser will not send the
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

You have to configure one more thing in your security configuration though: every firewall
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

You can configure the session handler to use a cookie based storage. There are various reasons to do this,
but generally speaking unless you have a very good one [you should avoid it](http://wonko.com/post/why-you-probably-shouldnt-use-cookies-to-store-session-data).

**WARNING**: The size limit of a cookie is 4KB, so make sure you are not storing objects or long
strings in the session.

```yaml
framework:
    session:
        handler_id: nelmio_security.session.handler

nelmio_security:
    cookie_session:
        enabled: true
        name: session
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
        report_uri: %router.request_context.base_url%/nelmio/xss/report
```

### Referrer Policy

Adds `Referrer-Policy` header to control the `Referer` header that is added
to requests made from your site, and for navigations away from your site by browsers.

You can specify multiple [referrer policies](https://www.w3.org/TR/referrer-policy/#referrer-policies).
The order of the policies is important. Browser will choose only the last policy they understand.
For example older browsers don’t understand the `strict-origin-when-cross-origin` policy.
A site can specify a `no-referrer` policy followed by a `strict-origin-when-cross-origin` policy:
older browsers will ignore the unknown `strict-origin-when-cross-origin` value and use `no-referrer`,
while newer browsers will use `strict-origin-when-cross-origin` because it is the last to be processed.

A referrer policy is:
  * [`no-referrer`](https://www.w3.org/TR/referrer-policy/#referrer-policy-no-referrer),
  * [`no-referrer-when-downgrade`](https://www.w3.org/TR/referrer-policy/#referrer-policy-no-referrer-when-downgrade),
  * [`same-origin`](https://www.w3.org/TR/referrer-policy/#referrer-policy-same-origin),
  * [`origin`](https://www.w3.org/TR/referrer-policy/#referrer-policy-origin),
  * [`strict-origin`](https://www.w3.org/TR/referrer-policy/#referrer-policy-strict-origin),
  * [`origin-when-cross-origin`](https://www.w3.org/TR/referrer-policy/#referrer-policy-origin-when-cross-origin),
  * [`strict-origin-when-cross-origin`](https://www.w3.org/TR/referrer-policy/#referrer-policy-strict-origin-when-cross-origin),
  * [`unsafe-url`](https://www.w3.org/TR/referrer-policy/#referrer-policy-unsafe-url),
  * [the empty string](https://www.w3.org/TR/referrer-policy/#referrer-policy-empty-string).

For better security of your site please use `no-referrer`, `same-origin`, `strict-origin` or `strict-origin-when-cross-origin`.

```yaml
nelmio_security:
    referrer_policy:
        enabled: true
        policies:
            - 'no-referrer'
            - 'strict-origin-when-cross-origin'
```

## License

Released under the MIT License, see LICENSE.
