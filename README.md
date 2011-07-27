# NelmioSecurityBundle

## About

The NelmioSecurityBundle provides additional security features for your Symfony2 application.

## Features

* **Signed Cookies**: Specify certain cookies to be signed, so that the user cannot modify
  them.

## Maximum Security Configuration

    nelmio_security:
        signed_cookie: ~ # signs/verifies all cookies

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
