NelmioSecurityBundle
====================

The NelmioSecurityBundle provides additional security features for your Symfony application.

Installation
------------

Require the ``nelmio/security-bundle`` package in your composer.json and update
your dependencies:

.. code-block:: terminal

    $ composer require nelmio/security-bundle

The bundle should be automatically enabled by `Symfony Flex`_. If you don't use
Flex, you'll need to manually enable the bundle by adding the following line in
the ``config/bundles.php`` file of your project::

    <?php
    // config/bundles.php

    return [
        // ...
        Nelmio\SecurityBundle\NelmioSecurityBundle::class => ['all' => true],
        // ...
    ];

If you don't have a ``config/bundles.php`` file in your project, chances are that
you're using an older Symfony version. In this case, you should have an
``app/AppKernel.php`` file instead. Edit such file::

    <?php
    // app/AppKernel.php

    // ...
    class AppKernel extends Kernel
    {
        public function registerBundles()
        {
            $bundles = [
                // ...

                new Nelmio\SecurityBundle\NelmioSecurityBundle(),
            ];

            // ...
        }

        // ...
    }

In order to inject ``ContentSecurityPolicyListener`` in a service, it needs to be manually configured:

.. code-block:: yaml

    # config/services.yaml
    services:
        App\CustomService:
            arguments:
                - '@nelmio_security.csp_listener'


Features
--------

* **Content Security Policy**: Cross site scripting attacks (XSS) can be
  mitigated in modern browsers using a policy which instructs the browser never
  to execute inline scripts, or never to load content from another domain than
  the page's domain.

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
  send `HSTS`_ headers so that modern browsers supporting it can make users use HTTPS
  even if they enter URLs without https, avoiding attacks on public Wi-Fi.

* **Flexible HTTPS/SSL Handling**: If you don't want to force all users to use HTTPS, you should
  at least use secure session cookies and force SSL for logged-in users. But then logged-in users
  appear logged-out when they access a non-HTTPS resource. This is not really a good solution.
  This will make the application detect logged-in users and redirect them to a secure URL,
  without making the session cookie insecure.

* **Disable Content Type Sniffing**: Require that scripts are loaded using the correct mime type.
  This disables the feature that some browsers have which uses content sniffing to determine if the response is a valid
  script file or not.

* (DEPRECATED) **XSS Protection**: Enables/Disables Microsoft XSS Protection on compatible browsers (IE 8 and newer).

* **Referrer Policy**: ``Referrer-Policy`` header is added to all responses to control the ``Referer`` header
  that is added to requests made from your site, and for navigations away from your site by browsers.

* **Permissions Policy**: ``Permissions-Policy`` header is added to control which features and APIs can be
  used in the browser.

Maximum Security Configuration
------------------------------

This is the configuration that provides maximum security protection, but you
should read on the next sections for detailed recommendations:

.. code-block:: yaml

    # config/packages/nelmio_security.yaml
    nelmio_security:
        # signs/verifies all cookies
        signed_cookie:
            names: ['*'] # Beware: Login won't work if all cookies are signed.
        # prevents framing of the entire site
        clickjacking:
            paths:
                '^/.*': DENY
            hosts:
                - '^foo\.com$'
                - '\.example\.org$'

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
                report-uri: '%router.request_context.base_url%/nelmio/csp/report'
                default-src:
                    - 'none'
                script-src:
                    - 'self'
                block-all-mixed-content: true # defaults to false, blocks HTTP content over HTTPS transport
                # upgrade-insecure-requests: true # defaults to false, upgrades HTTP requests to HTTPS transport

        # disables content type sniffing for script resources
        content_type:
            nosniff: true

        # Send a full URL in the ``Referer`` header when performing a same-origin request,
        # only send the origin of the document to secure destination (HTTPS->HTTPS),
        # and send no header to a less secure destination (HTTPS->HTTP).
        # If ``strict-origin-when-cross-origin`` is not supported, use ``no-referrer`` policy,
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

        permissions_policy:
            # Media permissions
            camera: []
            microphone: []

            # Location and sensors
            geolocation: []
            accelerometer: []
            gyroscope: []
            magnetometer: []

            # Privacy features
            interest_cohort: []           # Disable FLoC tracking

            # Payment and authentication
            payment: ['self']
            publickey_credentials_get: ['self']

            # Display and interaction
            fullscreen: ['self']
            picture_in_picture: ['self']
            autoplay: []

Content Security Policy
-----------------------

Using CSP you can set a policy which modern browsers understand and will honor.
The policy contains many different directives; ``default-src``, ``script-src``,
``object-src``, ``style-src``, ``img-src``, ``media-src``, ``frame-src``,
``font-src``, ``connect-src``, ``base-uri``, ``child-src``, ``form-action``,
``frame-ancestors``, ``plugin-types``, ``block-all-mixed-content``,
``upgrade-insecure-requests``, ``report-uri``, ``manifest-src``.

You can provide an array of directives per content type, except for ``block-all-mixed-content``
and ``upgrade-insecure-requests`` that only accept boolean values. Empty content
types will inherit from ``default-src``, specified content types will never inherit
from ``default-src``. Please see the `Content Security Policy 1.0`_ and
`Content Security Policy 2.0`_ specifications for details.

Each directive should be a domain, URI or keyword. The keyword ``'self'`` will
allow content from the same origin as the page. If you need to allow inline
scripts or ``eval()`` you can use ``'unsafe-inline'`` and ``'unsafe-eval'``.

.. caution::

    By using ``'unsafe-inline'`` or ``'unsafe-eval'`` you're effectively
    disabling the XSS protection mechanism of CSP.

Apart from content types, the policy also accepts ``report-uri`` which should be
a URI where a browser can POST a `JSON payload`_ to whenever a policy directive
is violated. As of v3.5, a ``report-to`` directive can be included as well to configure a
reporting endpoint (see `Reporting API`_), which is intended to replace the deprecated ``report-uri`` directive.

An optional ``content_types`` key lets you restrict the Content Security Policy
headers only on some HTTP response given their content type.

Finally, an optional ``hosts`` key lets you configure which hostnames (e.g. ``foo.example.org``)
the CSP rule should be enforced on. If the list is empty (it is by default), all
hostnames will use the CSP rule.

If the ``content_types`` and ``hosts`` options don’t fit your needs, you can also configure a service implementing
``Symfony\Component\HttpFoundation\RequestMatcherInterface`` as ``request_matcher``. Then the ``content_types`` and ``hosts``
options are no longer used.

.. code-block:: yaml

    # config/packages/nelmio_security.yaml
    nelmio_security:
        csp:
            enabled: true
            report_logger_service: logger
            request_matcher: null
            hosts: []
            content_types: []
            enforce:
                # see full description below
                level1_fallback: true
                # only send directives supported by the browser, defaults to false
                # this is a port of https://github.com/twitter/secureheaders/blob/83a564a235c8be1a8a3901373dbc769da32f6ed7/lib/secure_headers/headers/policy_management.rb#L97
                browser_adaptive:
                    enabled: false
                report-uri: '%router.request_context.base_url%/nelmio/csp/report'
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
                report-uri: '%router.request_context.base_url%/nelmio/csp/report'
                script-src:
                    - 'self'

The above configuration would enforce the following policy:

* Default is to allow from same origin as the page
* Frames only from secure YouTube connections
* JavaScript from same origin and from inline ``<script>`` tags
* Images from same origin, ``facebook.com`` and ``flickr.com``

Any violation of the enforced policy would be posted to ``/nelmio/csp/report``.

In addition, the configuration only reports but doesn't enforce the policy that
JavaScript may only be executed when it comes from the same server.

The bundle provides a default reporting implementation that logs violations as notices
to the default logger, to enable add the following to your routing.yml:

.. code-block:: yaml

    # config/routing.yaml
    nelmio_security:
        path:     /nelmio/csp/report
        defaults: { _controller: nelmio_security.csp_reporter_controller::indexAction }
        methods:  [POST]

(Optional) Use **report_logger_service** to log to the ``'security'`` channel:

.. code-block:: yaml

    # config/packages/nelmio_security.yaml
    nelmio_security:
        csp:
            report_logger_service: monolog.logger.security

(Optional) Disable **compat_headers** to avoid sending X-Content-Security-Policy
(IE10, IE11, Firefox < 23). This will mean those browsers get no CSP instructions.

.. code-block:: yaml

    # config/packages/nelmio_security.yaml
    nelmio_security:
        csp:
            compat_headers: false

Using browser adaptive directives
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The NelmioSecurityBundle can be configured to only send directives that can be
understood by the browser. This reduces noise provided via the report URI.
This is a direct port of what has been done in `Twitter SecureHeaders library`_.

Use the ``enabled`` key to enable it:

.. code-block:: yaml

    # config/packages/nelmio_security.yaml
    nelmio_security:
        csp:
            enforce:
                browser_adaptive:
                    enabled: true

.. caution::

    This will parse the user agent and can consume some CPU usage. You can
    specify a cached parser to avoid consuming too much CPU:

    .. code-block:: yaml

        # config/packages/nelmio_security.yaml
        nelmio_security:
            csp:
                enforce:
                    browser_adaptive:
                        enabled: true
                        parser: my_own_parser

And declare service ``my_own_parser`` based on one of the cached parser
NelmioSecurityBundle provides or your own one. For instance, using the ``PsrCacheUAFamilyParser``:

.. code-block:: xml

    <service id="my_own_parser" class="Nelmio\SecurityBundle\UserAgent\UAFamilyParser\PsrCacheUAFamilyParser">
      <argument type="service" id="app.my_cache.pool"/>
      <argument type="service" id="nelmio_security.ua_parser.ua_php"/>
      <argument>604800</argument>
    </service>

Have a look in the ``Nelmio\SecurityBundle\UserAgent\UAFamilyParser`` for these parsers.

Message digest for inline script handling
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

If you want to disable ``'unsafe-inline'`` on ``script-src`` or ``style-src``
(recommended), Nelmio Security Bundle comes out of the box with message digest
functionality. Twig is natively supported.

You can configure the algorithm used for message digest in the configuration.

.. code-block:: yaml

    # config/packages/nelmio_security.yaml
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

In your Twig template use the ``cspscript`` and ``cspstyle`` tags to automatically
compute the message digest and insert it in your headers.

.. code-block:: html+twig

    {% cspscript %}
    <script>
        window.api_key = '{{ api_key }}';
    </script>
    {% endcspscript %}

    {# ... #}

    {% cspstyle %}
    <style>
        body {
            background-color: '{{ bgColor }}';
        }
    </style>
    {% endcspstyle %}

If you're not using Twig, you can use message digest with the
``ContentSecurityPolicyListener``, it will automatically compute the message
digest and add it to the response CSP header::

    $listener->addScript("<script>
        window.api_key = '{{ api_key }}';
    </script>");


    $listener->addStyle("<style>
        body {
            background-color: '{{ bgColor }}';
        }
    </style>");

Nonce for inline script handling
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Content-Security-Policy specification also proposes a nonce implementation for
inlining. Nelmio Security Bundle comes out of the box with nonce functionality.
Twig is natively supported.

In your Twig template use the ``csp_nonce`` function to access the nonce for the
current request and add it to the response CSP header. If you do not request a
nonce, nonce will not be generated.

.. code-block:: html+twig

    <script nonce="{{ csp_nonce('script') }}">
        window.api_key = '{{ api_key }}';
    </script>

    {# ... #}

    <style nonce="{{ csp_nonce('style') }}">
        body {
            background-color: '{{ bgColor }}';
        }
    </style>

If you're not using Twig, you can use nonce functionality with the ``ContentSecurityPolicyListener``::

    // generates a nonce at first time, returns the same nonce once generated
    $listener->getNonce('script');
    // or
    $listener->getNonce('style');

Reporting
~~~~~~~~~

Using the ``report-uri`` you can easily collect violation using the ``ContentSecurityPolicyController``.
Here's an configuration example using ``routing.yml``:

.. code-block:: yaml

    # config/routes.yaml
    csp_report:
        path: /csp/report
        methods: [POST]
        defaults: { _controller: nelmio_security.csp_reporter_controller::indexAction }

This part of the configuration helps to filter noise collected by this endpoint:

.. code-block:: yaml

    # config/packages/nelmio_security.yaml
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

Signed Cookies
--------------

Ideally you should explicitly specify which cookies to sign. The reason for this
is simple. Cookies are sent with each request. Signatures are often longer than
the cookie values themselves, so signing everything would just needlessly slow
down your app and increase bandwidth usage for your users.

.. code-block:: yaml

    # config/packages/nelmio_security.yaml
    nelmio_security:
        signed_cookie:
            names: [test1, test2]

However, for simplicity reasons, and to start with a high security and optimize
later, you can specify ``*`` as a cookie name to have all cookies signed automatically.

.. code-block:: yaml

    # config/packages/nelmio_security.yaml
    nelmio_security:
        signed_cookie:
            names: ['*'] # Beware: Login won't work if all cookies are signed.

Additional, optional configuration settings:

.. code-block:: yaml

    # config/packages/nelmio_security.yaml
    nelmio_security:
        signed_cookie:
            secret: this_is_very_secret # defaults to global %secret% parameter
            hash_algo: sha512 # defaults to sha256, see ``hash_algos()`` for available algorithms

Upgrading the Hash Algorithm
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

With advancements in computational power and security research, upgrading to more secure hashing algorithms is
essential for maintaining application security. However, simply changing the `hash_algo` value could break existing
cookies. To facilitate a smooth transition, this bundle offers a `legacy_hash_algo` option. If your application
currently uses `sha-256` and you wish to upgrade to the more secure `sha3-256` algorithm, set `legacy_hash_algo`
to `sha256` and `hash_algo` to `sha3-256`.

.. code-block:: yaml

    # config/packages/nelmio_security.yaml
    nelmio_security:
        signed_cookie:
            hash_algo: sha3-256
            legacy_hash_algo: sha256

.. caution::

    The `legacy_hash_algo` option can expose your application to downgrade attacks and should only be used temporarily
    for backward compatibility.

Clickjacking Protection
-----------------------

Most websites do not use frames and do not need to be frame-able. This is a
common attack vector for which all current browsers (IE8+, Opera10.5+,
Safari4+, Chrome4+ and Firefox3.7+) have a solution. An extra header sent by
your site will tell the browser that it can not be displayed in a frame.
Browsers react by showing a short explanation instead of the content, or a blank page.

The valid values for the ``X-Frame-Options`` header are ``DENY``(prevent framing
from all pages) and ``SAMEORIGIN`` (prevent framing from all pages not on the
same domain). Additionally this bundle supports the ``ALLOW`` option which
skips the creation of the header for the matched URLs, if you want to allow a
few URLs and then DENY everything else.

One more option, as of yet `not well supported`_, is to use ``ALLOW-FROM uri``
where ``uri`` can be any origin URL, from ``example.org`` to
``https://example.org:123/sub/path``. This lets you specify exactly which domain
can embed your site, in case you have a multi-domain setup.

Default configuration (deny everything):

.. code-block:: yaml

    # config/packages/nelmio_security.yaml
    nelmio_security:
        clickjacking:
            paths:
                '^/.*': DENY
            content_types: []
            hosts: []

Allow list configuration (deny all but a few URLs):

.. code-block:: yaml

    # config/packages/nelmio_security.yaml
    nelmio_security:
        clickjacking:
            paths:
                '^/iframes/': ALLOW
                '^/business/': 'ALLOW-FROM https://biz.example.org'
                '^/local/': SAMEORIGIN
                '^/.*': DENY
            content_types: []
            hosts: []

Apply to certain hosts:

.. code-block:: yaml

    # config/packages/nelmio_security.yaml
    nelmio_security:
        clickjacking:
            paths:
                '^/iframes/': ALLOW
                '^/.*': DENY
            content_types: []
            hosts:
                - '^foo\.com$'
                - '\.example\.org$'

You can also of course only deny a few critical URLs, while leaving the rest alone:

.. code-block:: yaml

    # config/packages/nelmio_security.yaml
    nelmio_security:
        clickjacking:
            paths:
                '^/message/write': DENY
            content_types: []
            hosts: []

An optional ``content_types`` key lets you restrict the X-Frame-Options header
only on some HTTP response given their content type.

External Redirects Detection
----------------------------

This feature helps you detect and prevent redirects to external sites. This can
easily happen by accident if you carelessly take query parameters as redirection target.

You can log those (it's logged at warning level) by turning on logging:

.. code-block:: yaml

    # config/packages/nelmio_security.yaml
    nelmio_security:
        external_redirects:
            log: true

You can abort (they are replaced by a 403 response) the redirects:

.. code-block:: yaml

    # config/packages/nelmio_security.yaml
    nelmio_security:
        external_redirects:
            abort: true

Or you can override them, replacing the redirect's ``Location`` header by a
route name or another URL:

.. code-block:: yaml

    # config/packages/nelmio_security.yaml
    nelmio_security:
        external_redirects:
            # redirect to the 'home' route
            override: home
            # use this to redirect to another URL
            # override: /foo

If you want to display the URL that was blocked on the overriding page you can
specify the ``forward_as`` parameter, which defines which query parameter will
receive the URL. For example using the config below, doing a redirect to
``http://example.org/`` will be overridden to ``/external-redirect?redirUrl=http://example.org/``.

.. code-block:: yaml

    # config/packages/nelmio_security.yaml
    nelmio_security:
        external_redirects:
            # redirect and forward the overridden URL
            override: /external-redirect
            forward_as: redirUrl

Since it's quite common to have to redirect outside the website for legit
reasons, typically OAuth logins and such, you can allow a few domain names. All
their subdomains will be allowed as well, so you can allow your own website's
subdomains if needed.

.. code-block:: yaml

    # config/packages/nelmio_security.yaml
    nelmio_security:
        external_redirects:
            abort: true
            allow_list:
                - twitter.com
                - facebook.com

If you have a controller that can redirect to another host, you can also use `ExternalRedirectResponse` to allow the
redirect without having to configure the hosts globally. Any hosts passed to `ExternalRedirectResponse` are in
addition to those already configured globally.

.. code-block:: yaml

    # config/packages/nelmio_security.yaml
    nelmio_security:
        external_redirects:
            abort: true
            allow_list:
                - bar.com

.. code-block:: php

    use Nelmio\SecurityBundle\ExternalRedirect\ExternalRedirectResponse;

    // Will be allowed even though "foo.com" is not allowed globally through the config.
    return new ExternalRedirectResponse('https://foo.com', ['foo.com', 'auth-provider.test']);

    // Will not be allowed.
    return new ExternalRedirectResponse('https://not-allowed.com', ['foo.com', 'auth-provider.test']);

    // Will be allowed because "bar.com" is allowed globally through the config.
    return new ExternalRedirectResponse('https://bar.com', ['foo.com', 'auth-provider.test']);

Forced HTTPS/SSL Handling
-------------------------

By default, this option forces your entire site to use SSL, always. It redirect
all users reaching the site with a http:// URL to a https:// URL with a 302 response.

The base configuration for this is the following:

.. code-block:: yaml

    # config/packages/nelmio_security.yaml
    nelmio_security:
        forced_ssl: ~

If you turn this option on, it's recommended to also set your session cookie to
be secure, and all other cookies you send for that matter. You can do the former using:

.. code-block:: yaml

    # config/packages/framework.yaml
    framework:
        session:
            cookie_secure: true

To keep a few URLs from being force-redirected to SSL you can define an allowed
list of regular expressions:

.. code-block:: yaml

    # config/packages/nelmio_security.yaml
    nelmio_security:
        forced_ssl:
            enabled: true
            allow_list:
                - ^/unsecure/

To restrict the force-redirects to some hostnames only you can define a list of
hostnames as regular expressions:

.. code-block:: yaml

    # config/packages/nelmio_security.yaml
    nelmio_security:
        forced_ssl:
            enabled: true
            hosts:
                - ^\.example\.org$

To change the way the redirect is done to a permanent redirect for example, you can set:

.. code-block:: yaml

    # config/packages/nelmio_security.yaml
    nelmio_security:
        forced_ssl:
            enabled: true
            redirect_status_code: 301

Then if you want to push it further, you can enable `HTTP Strict Transport Security (HSTS)`_.
This is basically sending a header to tell the browser that your site must always
be accessed using SSL. If a user enters a ``http://`` URL, the browser will convert
it to ``https://`` automatically, and will do so before making any request, which
prevents man-in-the-middle attacks.

The browser will cache the value for as long as the specified ``hsts_max_age``
(in seconds), and if you turn on the ``hsts_subdomains`` option, the behavior
will be applied to all subdomains as well.

.. code-block:: yaml

    # config/packages/nelmio_security.yaml
    nelmio_security:
        forced_ssl:
            hsts_max_age: 2592000 # 30 days
            hsts_subdomains: true

You can also tell the browser to add your site to the list of known HSTS sites,
by enabling ``hsts_preload``. Once your site has appeared in the Chrome and
Firefox preload lists, then new users who come to your site will already be
redirected to HTTPS URLs.

.. code-block:: yaml

    # config/packages/nelmio_security.yaml
    nelmio_security:
        forced_ssl:
            hsts_max_age: 31536000 # 1 year
            hsts_preload: true

.. note::

    A value of at least 1 year is currently `required by Chrome`_ and
    `also required by Firefox`_. ``hsts_subdomains`` must also be enabled for
    preloading to work.

You can speed up the inclusion process by submitting your site to the `HSTS Preload List`_.

A small word of caution: While HSTS is great for security, it means that if the
browser can not establish your SSL certificate is valid, it will not allow the
user to query your site. That just means you should be careful and renew your
certificate in due time.

.. tip::

    Check `Can I use HSTS?`_ for the full information about its support in browsers.

Flexible HTTPS/SSL Handling
---------------------------

The best way to handle SSL securely is to enable it for your entire site.

However in some cases this is not desirable, be it for caching or performance
reasons, or simply because most visitors of your site are anonymous and don't
benefit much from the added privacy and security of SSL.

If you don't want to enable SSL across the board, you need to avoid that people
on insecure networks (typically open Wi-Fi) get their session cookie stolen by
sending it non-encrypted. The way to achieve this is to set your session cookie
to be secure as such - but don't do it just yet, keep reading to the end.

.. code-block:: yaml

    # config/packages/framework.yaml
    framework:
        session:
            cookie_secure: true

If you use the remember-me functionality, you would also mark that one as secure:

.. code-block:: yaml

    # config/packages/security.yaml
    security:
        firewalls:
            somename:
                remember_me:
                    secure: true

Now if you do this, you have two problems. First, insecure pages will not be
able to use the session anymore, which can be inconvenient. Second, if a logged
in user gets to a non-HTTPS page of your site, it is seen as anonymous since
his browser will not send the session cookie. To fix this, this bundle sets a
new insecure cookie(``flexible_ssl.cookie_name``, defaults to ``auth``) once a
user logs in. That way, if any page is accessed insecurely by a logged in user,
he is redirected to the secure version of the page, and his session is then
visible to the framework.

Enabling the ``flexible_ssl`` option of the NelmioSecurityBundle will make sure
that logged-in users are always seeing secure pages, and it will make sure
their session cookie is secure, but anonymous users will still be able to have
an insecure session, if you need to use it to store non critical data like
language settings and whatnot. The remember-me cookie will also be made always
secure, even if you leave the setting to false.

.. code-block:: yaml

    # config/packages/nelmio_security.yaml
    nelmio_security:
        flexible_ssl:
            cookie_name: auth
            unsecured_logout: false

You have to configure one more thing in your security configuration though:
every firewall should have our logout listener added, so that the special
``auth`` cookie can be cleared when users log out. You can do it as such:

.. code-block:: yaml

    # config/packages/security.yaml
    security:
        firewalls:
            somename:
                # ...
                logout:
                    handlers:
                        - nelmio_security.flexible_ssl_listener

On logout, if you would like users to be redirected to an unsecure page set
``unsecured_logout`` to true.

Content Type Sniffing
---------------------

Disables the content type sniffing for script resources. Forces the browser to only execute script files with valid
content type headers. This requires using `a non-standard nosniff header from Microsoft`_.

.. code-block:: yaml

    # config/packages/nelmio_security.yaml
    nelmio_security:
        content_type:
            nosniff: true

XSS Protection (DEPRECATED)
--------------------------

.. caution::

    This feature is non-standard and deprecated. It is recommended to use CSP instead : https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection

Enables or disables Microsoft XSS Protection on compatible browsers.
This requires using `a non-standard X-XSS-Protection header from Microsoft`_.

.. code-block:: yaml

    # config/packages/nelmio_security.yaml
    nelmio_security:
        xss_protection:
            enabled: true
            mode_block: true
            report_uri: '%router.request_context.base_url%/nelmio/xss/report'

Referrer Policy
---------------

Adds ``Referrer-Policy`` header to control the ``Referer`` header that is added
to requests made from your site, and for navigations away from your site by browsers.

You can specify multiple `referrer policies`_. The order of the policies is
important. Browser will choose only the last policy they understand. For
example older browsers don't understand the ``strict-origin-when-cross-origin``
policy. A site can specify a ``no-referrer`` policy followed by a
``strict-origin-when-cross-origin`` policy: older browsers will ignore the
unknown ``strict-origin-when-cross-origin`` value and use ``no-referrer``,
while newer browsers will use ``strict-origin-when-cross-origin`` because it is
the last to be processed.

These are the valid referrer policies:

* `no-referrer <https://www.w3.org/TR/referrer-policy/#referrer-policy-no-referrer>`_
* `no-referrer-when-downgrade <https://www.w3.org/TR/referrer-policy/#referrer-policy-no-referrer-when-downgrade>`_
* `same-origin <https://www.w3.org/TR/referrer-policy/#referrer-policy-same-origin>`_
* `origin <https://www.w3.org/TR/referrer-policy/#referrer-policy-origin>`_
* `strict-origin <https://www.w3.org/TR/referrer-policy/#referrer-policy-strict-origin>`_
* `origin-when-cross-origin <https://www.w3.org/TR/referrer-policy/#referrer-policy-origin-when-cross-origin>`_
* `strict-origin-when-cross-origin <https://www.w3.org/TR/referrer-policy/#referrer-policy-strict-origin-when-cross-origin>`_
* `unsafe-url <https://www.w3.org/TR/referrer-policy/#referrer-policy-unsafe-url>`_
* `an empty string <https://www.w3.org/TR/referrer-policy/#referrer-policy-empty-string>`_

For better security of your site please use ``no-referrer``, ``same-origin``,
``strict-origin`` or ``strict-origin-when-cross-origin``.

.. code-block:: yaml

    # config/packages/nelmio_security.yaml
    nelmio_security:
        referrer_policy:
            enabled: true
            policies:
                - 'no-referrer'
                - 'strict-origin-when-cross-origin'

Permissions Policy
------------------

The ``Permissions-Policy`` header allows you to control which web platform features
can be used in the browser. This helps prevent malicious third-party content from
accessing sensitive APIs like camera, microphone, or geolocation.

Basic configuration:

.. code-block:: yaml

    # config/packages/nelmio_security.yaml
    nelmio_security:
        permissions_policy:
            payment: default              # Use default allowlist for payment directive
            camera: []                    # Disable camera for all origins
            microphone: ['self']          # Allow microphone for same origin only
            geolocation: ['*']            # Allow geolocation for all origins
            payment: ['self', 'https://payments.example.com']

The above configuration would generate the following header:

.. code-block:: text

    Permissions-Policy: camera=(), microphone=(self), geolocation=(*), payment=(self "https://payments.example.com")

Supported directive values:

* ``~`` or ``null`` to disable the directive entirely (default)
* ``default`` to use the default allowlist for the directive defined in the _`specifications`: https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Permissions-Policy
* ``[]`` or empty array - Disallows the feature for all origins
* ``['self']`` - Allows the feature for the same origin as the document
* ``['*']`` - Allows the feature for all origins
* ``['src']`` - Allows the feature for the same origin as the src attribute (iframe context)
* ``['https://example.com']`` - Allows the feature for specific origins (URLs must be quoted)

Common permissions policies:

.. code-block:: yaml

    # config/packages/nelmio_security.yaml
    nelmio_security:
        permissions_policy:
            # Media permissions
            camera: []
            microphone: []

            # Location and sensors
            geolocation: []
            accelerometer: []
            gyroscope: []
            magnetometer: []

            # Privacy features
            interest_cohort: []           # Disable FLoC tracking

            # Payment and authentication
            payment: ['self']
            publickey_credentials_get: ['self']

            # Display and interaction
            fullscreen: ['self']
            picture_in_picture: ['self']
            autoplay: []

Available directive names (automatically converted from snake_case to kebab-case):

.. list-table:: Permissions-Policy Directives & Default Allowlist
   :header-rows: 1
   :widths: 40 40

   * - Directive
     - Default allowlist
   * - accelerometer
     - self
   * - ambient_light_sensor
     - self
   * - attribution_reporting
     - *
   * - autoplay
     - self
   * - bluetooth
     - self
   * - browsing_topics
     - *
   * - camera
     - self
   * - captured_surface_control
     - self
   * - compute_pressure
     - self
   * - cross_origin_isolated
     - self
   * - deferred_fetch
     - self
   * - deferred_fetch_minimal
     - *
   * - display_capture
     - self
   * - encrypted_media
     - self
   * - fullscreen
     - self
   * - gamepad
     - self
   * - geolocation
     - self
   * - gyroscope
     - self
   * - hid
     - self
   * - identity_credentials_get
     - self
   * - idle_detection
     - self
   * - interest_cohort
     - none
   * - language_detector
     - self
   * - local_fonts
     - self
   * - magnetometer
     - self
   * - microphone
     - self
   * - midi
     - self
   * - otp_credentials
     - self
   * - payment
     - self
   * - picture_in_picture
     - *
   * - publickey_credentials_create
     - self
   * - publickey_credentials_get
     - self
   * - screen_wake_lock
     - self
   * - serial
     - self
   * - speaker_selection
     - self
   * - storage_access
     - *
   * - summarizer
     - self
   * - translator
     - self
   * - usb
     - self
   * - web_share
     - self
   * - window_management
     - self
   * - xr_spatial_tracking
     - self

.. caution::

    Some directive names are experimental and may not be supported by all browsers.
    Using unsupported directives will generate console warnings in browsers like Chrome.

Browser compatibility:

* **Chrome 88+**: Full support
* **Edge 88+**: Full support
* **Firefox**: Not supported (header is skipped automatically)
* **Safari**: Not supported (header is skipped automatically)

The bundle automatically detects Firefox and Safari user agents and skips sending
the ``Permissions-Policy`` header to avoid compatibility issues.

.. _`Symfony Flex`: https://symfony.com/doc/current/setup/flex.html
.. _`HSTS`: http://tools.ietf.org/html/draft-hodges-strict-transport-sec-02
.. _`Content Security Policy 1.0`: https://www.w3.org/TR/2012/CR-CSP-20121115/
.. _`Content Security Policy 2.0`: https://www.w3.org/TR/2015/CR-CSP2-20150721/
.. _`JSON payload`: https://developer.mozilla.org/en-US/docs/Security/CSP/Using_CSP_violation_reports#Sample_violation_report
.. _`Twitter SecureHeaders library`: https://github.com/twitter/secureheaders
.. _`not well supported`: https://developer.mozilla.org/en-US/docs/Web/HTTP/X-Frame-Options
.. _`HTTP Strict Transport Security (HSTS)`: http://tools.ietf.org/html/draft-hodges-strict-transport-sec-02
.. _`required by Chrome`: https://hstspreload.org/
.. _`also required by Firefox`: https://blog.mozilla.org/security/2012/11/01/preloading-hsts/
.. _`HSTS Preload List`: https://hstspreload.org/
.. _`Can I use HSTS?`: http://caniuse.com/#feat=stricttransportsecurity
.. _`a non-standard nosniff header from Microsoft`: http://msdn.microsoft.com/en-us/library/ie/gg622941.aspx
.. _`a non-standard X-XSS-Protection header from Microsoft`: http://blogs.msdn.com/b/ieinternals/archive/2011/01/31/controlling-the-internet-explorer-xss-filter-with-the-x-xss-protection-http-header.aspx
.. _`referrer policies`: https://www.w3.org/TR/referrer-policy/#referrer-policies
.. _`Reporting API`: https://www.w3.org/TR/reporting-1/
.. _`permissions policy`: https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Permissions-Policy
