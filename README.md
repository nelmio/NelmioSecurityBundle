# NelmioSecurityBundle

## About

The NelmioSecurityBundle provides additional security features for your Symfony2 application.

## Features

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

* **Flexible HTTPS/SSL Handling**: Usually you have to either force all users to use HTTPS or have
  logged-in users appear logged-out when they access a non-HTTPS resource. This is not really a
  good solution. This will make the application detect logged-in users and redirect them to a
  secure URL, without making the session cookie insecure.

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

        # flexible HTTPS handling, please read the detailed config info
        # and make sure you have SSL working on your site before enabling this
    #    flexible_ssl:
    #        cookie_name: auth

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

* **Flexible HTTPS/SSL Handling**:

The best way to handle SSL securely is to [enable it for your entire site](http://symfony.com/doc/2.0/cookbook/security/force_https.html).
However in some cases this is not desirable, be it for caching or performance reasons,
or simply because most visitors of your site are anonymous and don't benefit much from SSL.

If you don't want to enable SSL across the board, you need to avoid that people on insecure
networks (typically open Wi-Fi) get their session cookie stolen by sending it non-encrypted.
The way to achieve this is to set your session cookie to be secure as such - but don't do
it just yet, keep reading to the end.

    framework:
        session:
            secure: true

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
to use it to store non critical data like language settings and whatnot. That is why you
should leave your framework.session.cookie setting to false. The remember-me cookie will
also be made always secure, even if you leave the setting to false.

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
