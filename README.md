# NelmioSecurityBundle

## About

The NelmioSecurityBundle provides additional security features for your Symfony2 application.

## Features

* **Signed Cookies**: Specify certain cookies to be signed, so that the user cannot modify
  them.

* **Clickjacking Protection**: X-Frame-Options header is added to all responses to prevent your
  site from being put in a frame/iframe. This can have serious security implications as it has
  been demonstrated time and time again with Facebook and others. You can allow framing of your
  site from itself or from anywhere on a per-URL basis.

* **External Redirects Detection**: Redirecting from your site to arbitrary URLs based on user
  input can be exploited to confuse users into clicking links that seemingly point to valid
  sites while they in fact lead to malicious content. It also may be possible to gain PageRank
  that way.

## Maximum Security Configuration (Read on for detailed recommendations!)

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

## Configuration Detail

* **Signed Cookies**:

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
            secret: this_is_very_secret # defaults to global %secret%
            hash_algo: sha1 # defaults to sha256

* **Clickjacking Protection**:

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

* **External Redirects Detection**:

This feature helps you detect and prevent redirects to external sites. This can easily happen
by accident if you carelessly take query parameters as redirection target.

You can only log those (it's logged at warning level) by turning on logging:

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

## Installation

Put the NelmioSecurityBundle into the ``vendor/bundles/Nelmio`` directory:

    $ git clone git://github.com/nelmio/NelmioSecurityBundle.git vendor/bundles/Nelmio/SecurityBundle

Register the `Nelmio` namespace in your project's autoload script (app/autoload.php):

    $loader->registerNamespaces(array(
        'Nelmio'                        => __DIR__.'/../vendor/bundles',
    ));

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
