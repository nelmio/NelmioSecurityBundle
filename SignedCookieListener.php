<?php

/*
 * This file is part of the Nelmio SecurityBundle.
 *
 * (c) Nelmio <hello@nelm.io>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Nelmio\SecurityBundle;

use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\ResponseHeaderBag;
use Symfony\Component\HttpKernel\Event\FilterResponseEvent;
use Symfony\Component\HttpKernel\Event\GetResponseEvent;

class SignedCookieListener
{
    private $signer;
    private $signedCookieNames;

    public function __construct(Signer $signer, $signedCookieNames)
    {
        $this->signer = $signer;
        $this->signedCookieNames = $signedCookieNames;
    }

    public function onKernelRequest(GetResponseEvent $e)
    {
        $request = $e->getRequest();

        foreach ($this->signedCookieNames as $name) {
            if ($request->cookies->has($name)) {
                $cookie = $request->cookies->get($name);
                if ($this->signer->verifySignedValue($cookie)) {
                    $request->cookies->set($name, $this->signer->getVerifiedRawValue($cookie));
                } else {
                    $request->cookies->remove($name);
                }
            }
        }
    }

    public function onKernelResponse(FilterResponseEvent $e)
    {
        $response = $e->getResponse();
        $cookies = $response->headers->getCookies(ResponseHeaderBag::COOKIES_ARRAY);

        foreach ($this->signedCookieNames as $name) {
            if (null !== $cookie = $this->findCookieByName($name, $cookies)) {
                $response->headers->removeCookie($cookie->getName(), $cookie->getPath(), $cookie->getDomain());
                $signedCookie = new Cookie(
                    $name,
                    $this->signer->getSignedValue($cookie->getValue()),
                    $cookie->getExpiresTime(),
                    $cookie->getPath(),
                    $cookie->getDomain(),
                    $cookie->isSecure(),
                    $cookie->isHttpOnly()
                );
                $response->headers->setCookie($signedCookie);
            }
        }
    }

    private function findCookieByName($name, $cookieContainer)
    {
        foreach ($cookieContainer as $host => $paths) {
            foreach ($paths as $path => $cookies) {
                if (isset($cookies[$name])) {
                    return $cookies[$name];
                }
            }
        }
    }
}
