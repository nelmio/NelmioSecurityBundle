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
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\Event\GetResponseEvent;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;

/**
 * @final
 */
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

    /**
     * @param GetResponseEvent|RequestEvent $e
     */
    public function onKernelRequest($e)
    {
        // Compatibility with Symfony < 5 and Symfony >=5
        if (!$e instanceof GetResponseEvent && !$e instanceof RequestEvent) {
            throw new \InvalidArgumentException(\sprintf('Expected instance of type %s, %s given', \class_exists(RequestEvent::class) ? RequestEvent::class : GetResponseEvent::class, \is_object($e) ? \get_class($e) : \gettype($e)));
        }

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

    /**
     * @param FilterResponseEvent|ResponseEvent $e
     */
    public function onKernelResponse($e)
    {
        // Compatibility with Symfony < 5 and Symfony >=5
        if (!$e instanceof FilterResponseEvent && !$e instanceof ResponseEvent) {
            throw new \InvalidArgumentException(\sprintf('Expected instance of type %s, %s given', \class_exists(ResponseEvent::class) ? ResponseEvent::class : FilterResponseEvent::class, \is_object($e) ? \get_class($e) : \gettype($e)));
        }

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
                    $cookie->isHttpOnly(),
                    method_exists($cookie, 'isRaw') ? $cookie->isRaw() : null,
                    method_exists($cookie, 'getSameSite') ? $cookie->getSameSite() : null
                );
                $response->headers->setCookie($signedCookie, $cookie->getPath(), $cookie->getDomain());
            }
        }
    }
}
