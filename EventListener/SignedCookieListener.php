<?php

/*
 * This file is part of the Nelmio SecurityBundle.
 *
 * (c) Nelmio <hello@nelm.io>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Nelmio\SecurityBundle\EventListener;

use Nelmio\SecurityBundle\Signer;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpKernel\Event\FilterResponseEvent;
use Symfony\Component\HttpKernel\Event\GetResponseEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;

class SignedCookieListener
{
    private $signer;
    private $signedCookieNames;

    public function __construct(Signer $signer, $signedCookieNames)
    {
        $this->signer = $signer;
        if (in_array('*', $signedCookieNames, true)) {
            $this->signedCookieNames = true;
        } else {
            $this->signedCookieNames = $signedCookieNames;
        }
    }

    public function onKernelRequest(GetResponseEvent $e)
    {
        if (HttpKernelInterface::MASTER_REQUEST !== $e->getRequestType()) {
            return;
        }

        $request = $e->getRequest();

        $names = $this->signedCookieNames === true ? $request->cookies->keys() : $this->signedCookieNames;
        foreach ($names as $name) {
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
        if (HttpKernelInterface::MASTER_REQUEST !== $e->getRequestType()) {
            return;
        }

        $response = $e->getResponse();

        foreach ($response->headers->getCookies() as $cookie) {
            if (true === $this->signedCookieNames || in_array($cookie->getName(), $this->signedCookieNames, true)) {
                $response->headers->removeCookie($cookie->getName(), $cookie->getPath(), $cookie->getDomain());
                $signedCookie = new Cookie(
                    $cookie->getName(),
                    $this->signer->getSignedValue($cookie->getValue()),
                    $cookie->getExpiresTime(),
                    $cookie->getPath(),
                    $cookie->getDomain(),
                    $cookie->isSecure(),
                    $cookie->isHttpOnly()
                );
                $response->headers->setCookie($signedCookie, $cookie->getPath(), $cookie->getDomain());
            }
        }
    }
}
