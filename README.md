# NelmioSecurityBundle

## About

The NelmioSecurityBundle provides additional security features for your Symfony2 application.

## Features

* **[Content Security Policy](#content-security-policy)**: Cross site scripting attacks (XSS) can be mitigated
in modern browsers using a policy which instructs the browser never to execute inline scripts, or never to
load content from another domain than the page's domain.

* **[Signed Cookies](#signed-cookies)**: Specify certain cookies to be signed, so that the user cannot modify
  them. Note that they will not be encrypted, but signed only. The contents will still be
  visible to the user.

* **[Encrypted Cookies](#encrypted-cookies)**: Specify certain cookies to be encrypted, so that the value cannot be
  read. When you retreive the cookie it will be automatically decrypted.

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

## Maximum Security Configuration (Read on for detailed recommendations!)

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
            default: [ self ]

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

## Configuration Detail

### Content Security Policy:

Using CSP you can set a policy which modern browsers understand and will honor. The policy contains nine different
content types; `default`, `script`, `object`, `style`, `img`, `media`, `frame`, `font`, `connect`. You can provide
an array of directives per content type. Empty content types will inherit from `default`, specified content types
will never inherit from `default`.

Each directive should be a domain, URI or keyword. The keyword `self` will allow content from the same origin as
the page. If you need to allow inline scripts or `eval()` you can use `unsafe-inline` and `unsafe-eval`.

**WARNING:** By using `unsafe-inline` or `unsafe-eval` you're effectively disabling the XSS protection mechanism of CSP.

Apart from content types, the policy also accepts `report_uri` which should be a URI where a browser can POST a
[JSON payload](https://developer.mozilla.org/en-US/docs/Security/CSP/Using_CSP_violation_reports#Sample_violation_report)
to whenever a policy directive is violated. Setting `report_only` to `true` will enable reporting but the policy
will not be enforced.

    nelmio_security:
        csp:
            report_uri: /report
            report_only: false
            default: [ self ]
            frame: [ 'https://www.youtube.com' ]
            script:
                - self
                - 'https:'
            img:
                - self
                - facebook.com
                - flickr.com

The above configuration would allow:

* Default is to allow from same origin as the page
* Frames only from secure youtube connections
* JavaScript from same origin and any secure external URL
* Images from same origin, `facebook.com` and `flickr.com`

And would post any violations to /report

### **Signed Cookies**:

Ideally you should explicitly specify which cookies to sign. The reason for this is simple.
Cookies are sent with each request. Signatures are often longer than the cookie values themselves,
so signing everything would just needlessly slow down your app and increase bandwidth usage for
your users.

    nelmio_security:
        signed_cookie:
            names: [test1, test2]

However, for simplicity reasons, and to start with a high security and optimize later, you can
specify '*' as a cookie name to have all cookies signed automatically.

    nelmio_security:
        signed_cookie:
            names: ['*']

Additional, optional configuration settings:

    nelmio_security:
        signed_cookie:
            secret: this_is_very_secret # defaults to global %secret% parameter
            hash_algo: sha512 # defaults to sha256, see `hash_algos()` for available algorithms

### **Encrypted Cookies**:

Encrypts the cookie values using `nelmio_security.encrypted_cookie.secret`. It works the same as
Signed Cookies:

    nelmio_security:
        encrypted_cookie:
            names: [test1, test2]

Additional, optional configuration settings:

    nelmio_security:
        encrypted_cookie:
            secret: this_is_very_secret # defaults to global %secret% parameter
            algorithm: rijndael-256 # defaults to rijndael-128, see `mcrypt_list_algorithms()` for available algorithms

### **Clickjacking Protection**:

Most websites do not use frames and do not need to be frame-able. This is a common attack vector
for which all current browsers (IE8+, Opera10.5+, Safari4+, Chrome4+ and Firefox3.7+) have a
solution. An extra header sent by your site will tell the browser that it can not be displayed in
an frame. Browsers react by showing a short explanation instead of the content, or a blank page.

The valid values for the `X-Frame-Options` header are `DENY` (prevent framing from all pages) and
`SAMEORIGIN` (prevent framing from all pages not on the same domain). Additionally this bundle
supports the `ALLOW` option which skips the creation of the header for the matched URLs, if you
want to whitelist a few URLs and then DENY everything else.

Default configuration (deny everything):

    nelmio_security:
        clickjacking:
            paths:
                '^/.*': DENY

Whitelist configuration (deny all but a few URLs):

    nelmio_security:
        clickjacking:
            paths:
                '^/iframes/': ALLOW
                '^/local/': SAMEORIGIN
                '^/.*': DENY

You can also of course only deny a few critical URLs, while leaving the rest alone:

    nelmio_security:
        clickjacking:
            paths:
                '^/message/write': DENY

### **External Redirects Detection**:

This feature helps you detect and prevent redirects to external sites. This can easily happen
by accident if you carelessly take query parameters as redirection target.

You can log those (it's logged at warning level) by turning on logging:

    nelmio_security:
        external_redirects:
            log: true

You can abort (they are replaced by a 403 response) the redirects:

    nelmio_security:
        external_redirects:
            abort: true

Or you can override them, replacing the redirect's `Location` header by a route name or
another URL:

    # redirect to the 'home' route
    nelmio_security:
        external_redirects:
            override: home

    # redirect to another URL
    nelmio_security:
        external_redirects:
            override: /foo

If you want to display the URL that was blocked on the overriding page you can
specify the `forward_as` parameter, which defines which query parameter will
receive the URL. For example using the config below, doing a redirect to
`http://example.org/` will be overridden to `/external-redirect?redirUrl=http://example.org/`.

    # redirect and forward the overridden URL
    nelmio_security:
        external_redirects:
            override: /external-redirect
            forward_as: redirUrl

Since it's quite common to have to redirect outside the website for legit reasons,
typically OAuth logins and such, you can whitelist a few domain names. All their subdomains
will be whitelisted as well, so that allows you to whitelist your own website's subdomains
if needed.

    nelmio_security:
        external_redirects:
            abort: true
            whitelist:
                - twitter.com
                - facebook.com

### **Forced HTTPS/SSL Handling**:

By default, this option forces your entire site to use SSL, always. It redirect all users
reaching the site with a http:// URL to a https:// URL.

The base configuration for this is the following:

    nelmio_security:
        forced_ssl: ~

If you turn this option on, it's recommended to also set your session cookie to be secure,
and all other cookies your send for that matter. You can do the former using:

    framework:
        session:
            cookie_secure: true

To keep a few URLs from being force-redirected to SSL you can define a whitelist of regular
expressions:

    nelmio_security:
        forced_ssl:
            enabled: true
            whitelist:
                - ^/unsecure/

Then if you want to push it further, you can enable
[HTTP Strict Transport Security (HSTS)](http://tools.ietf.org/html/draft-hodges-strict-transport-sec-02).
This is basically sending a header to tell the browser that your site must always be
accessed using SSL. If a user enters a http:// URL, the browser will convert it to https://
automatically, and will do so before making any request, which prevents man-in-the-middle
attacks.

The browser will cache the value for as long as the specified `hsts_max_age` (in seconds), and if
you turn on the `hsts_subdomains` option, the behavior will be applied to all subdomains as well.

    nelmio_security:
        forced_ssl:
            hsts_max_age: 2592000 # 30 days
            hsts_subdomains: false

A small word of caution: While HSTS is great for security, it means that if the browser
can not establish your SSL certificate is valid, it will not allow the user to query your site.
That just means you should be careful and renew your certificate in due time.

Note: HSTS presently (Aug. 2013) only works in Firefox 4+, Chrome 4+ and Opera 12+.

### **Flexible HTTPS/SSL Handling**:

The best way to handle SSL securely is to enable it for your entire site.

However in some cases this is not desirable, be it for caching or performance reasons,
or simply because most visitors of your site are anonymous and don't benefit much from the
added privacy and security of SSL.

If you don't want to enable SSL across the board, you need to avoid that people on insecure
networks (typically open Wi-Fi) get their session cookie stolen by sending it non-encrypted.
The way to achieve this is to set your session cookie to be secure as such - but don't do
it just yet, keep reading to the end.

    framework:
        session:
            cookie_secure: true

If you use the remember-me functionality, you would also mark that one as secure:

    security:
        firewalls:
            somename:
                remember_me:
                    secure: true

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

    nelmio_security:
        flexible_ssl:
            cookie_name: auth
            unsecured_logout: false

You have to configure one more thing in your security configuration though, every firewall
should have our logout listener added, so that the special `auth` cookie can be cleared when
users log out. You can do it as such:

    security:
        firewalls:
            somename:
                # ...
                logout:
                    handlers:
                        - nelmio_security.flexible_ssl_listener

On logout, if you would like users to be redirected to an unsecure page set ``unsecured_logout``
to true.

### Cookie Session Handler:

You can configure the session handler to use a cookie based storage. There are various reasons to do this, but generally speaking unless you have a very good one [you should avoid it](http://wonko.com/post/why-you-probably-shouldnt-use-cookies-to-store-session-data).

**WARNING**: by default the session is not encrypted, it is your responsibility to properly
configure the Encrypted Cookies section to include the session cookie (default name: session).
The size limit of a cookie is 4KB, so make sure you are not storing objects or long
strings in the session.

    framework:
        session:
            handler_id: nelmio_security.session.handler

    nelmio_security:
        cookie_session:
            enabled: true
            cookie_name: session

        encrypted_cookie:
            names: [session]

## Installation

Add a requirement in your composer.json for the `nelmio/security-bundle` package:

            "nelmio/security-bundle": "~1.0"

Add the NelmioSecurityBundle to your application's kernel:

    public function registerBundles()
    {
        $bundles = array(
            ...
            new Nelmio\SecurityBundle\NelmioSecurityBundle(),
            ...
        );
        ...
    }

## License

Released under the MIT License, see LICENSE.
