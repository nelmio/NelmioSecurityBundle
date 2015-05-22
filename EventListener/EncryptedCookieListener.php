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

use Nelmio\SecurityBundle\Encrypter;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpKernel\Event\FilterResponseEvent;
use Symfony\Component\HttpKernel\Event\GetResponseEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;

class EncryptedCookieListener
{
    private $encrypter;
    private $encryptedCookieNames;

    public function __construct(Encrypter $encrypter, $encryptedCookieNames)
    {
        $this->encrypter = $encrypter;
        if (in_array('*', $encryptedCookieNames, true)) {
            $this->encryptedCookieNames = true;
        } else {
            $this->encryptedCookieNames = $encryptedCookieNames;
        }
    }

    public function onKernelRequest(GetResponseEvent $e)
    {
        if (HttpKernelInterface::MASTER_REQUEST !== $e->getRequestType()) {
            return;
        }

        $request = $e->getRequest();

        $names = $this->encryptedCookieNames === true ? $request->cookies->keys() : $this->encryptedCookieNames;
        foreach ($names as $name) {
            if ($request->cookies->has($name)) {
                $cookie = $request->cookies->get($name);
                if ($value = $this->encrypter->decrypt($cookie)) {
                    $request->cookies->set($name, $value);
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
            if (true === $this->encryptedCookieNames || in_array($cookie->getName(), $this->encryptedCookieNames, true)) {
                $response->headers->removeCookie($cookie->getName(), $cookie->getPath(), $cookie->getDomain());
                $encryptedCookie = new Cookie(
                    $cookie->getName(),
                    $this->encrypter->encrypt($cookie->getValue()),
                    $cookie->getExpiresTime(),
                    $cookie->getPath(),
                    $cookie->getDomain(),
                    $cookie->isSecure(),
                    $cookie->isHttpOnly()
                );
                $response->headers->setCookie($encryptedCookie, $cookie->getPath(), $cookie->getDomain());
            }
        }
    }
}
