# NelmioSecurityBundle

## About

The NelmioSecurityBundle provides additional security features for your Symfony2 application.

## Features

* **Signed Cookies**: Specify certain cookies to be signed, so that the user cannot modify
  them.

* **Clickjacking Protection**: X-Frame-Options header is added to all responses to prevent your
  site from being put in a frame/iframe. You can allow framing from the site itself or from
  anywhere on a per-URL basis.

## Maximum Security Configuration

    nelmio_security:
        signed_cookie: ~ # signs/verifies all cookies
        clickjacking: ~ # prevents framing of the entire site

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
solution.

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
