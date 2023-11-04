<?php

declare(strict_types=1);

/*
 * This file is part of the Nelmio SecurityBundle.
 *
 * (c) Nelmio <hello@nelm.io>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Nelmio\SecurityBundle\EventListener;

use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\Security\Http\Event\InteractiveLoginEvent;
use Symfony\Component\Security\Http\Event\LogoutEvent;

final class FlexibleSslListener
{
    private string $cookieName;
    private bool $unsecuredLogout;
    private EventDispatcherInterface $dispatcher;

    public function __construct(string $cookieName, bool $unsecuredLogout, EventDispatcherInterface $dispatcher)
    {
        $this->cookieName = $cookieName;
        $this->unsecuredLogout = $unsecuredLogout;
        $this->dispatcher = $dispatcher;
    }

    public function onKernelRequest(RequestEvent $e): void
    {
        if (!$e->isMainRequest()) {
            return;
        }

        $request = $e->getRequest();

        // force users to use ssl if the auth cookie is present
        if ('1' === $request->cookies->get($this->cookieName) && !$request->isSecure()) {
            $e->setResponse(new RedirectResponse('https://'.substr($request->getUri(), 7)));
        }
    }

    public function onLogin(InteractiveLoginEvent $e): void
    {
        $this->dispatcher->addListener('kernel.response', [$this, 'onPostLoginKernelResponse'], -1000);
    }

    public function onPostLoginKernelResponse(ResponseEvent $e): void
    {
        if (!$e->isMainRequest()) {
            return;
        }

        $response = $e->getResponse();

        $longestExpire = 0;
        foreach ($response->headers->getCookies() as $cookie) {
            // find longest expiration time
            $longestExpire = max($longestExpire, $cookie->getExpiresTime());
            if (!$cookie->isSecure()) {
                // force existing cookies (remember-me most likely) to be secure
                $response->headers->setCookie(new Cookie(
                    $cookie->getName(),
                    $cookie->getValue(),
                    $cookie->getExpiresTime(),
                    $cookie->getPath(),
                    $cookie->getDomain(),
                    true,
                    $cookie->isHttpOnly(),
                    $cookie->isRaw(),
                    $cookie->getSameSite()
                ));
            }
        }

        if (null === $e->getRequest()->cookies->get($this->cookieName)) {
            // set the auth cookie
            $response->headers->setCookie(new Cookie(
                $this->cookieName,
                '1',
                $longestExpire,
                '/',
                null,
                false,
                false,
                false,
                Cookie::SAMESITE_LAX
            ));
        }

        // force session cookie to be secure
        $params = session_get_cookie_params();
        $response->headers->setCookie(new Cookie(
            session_name(),
            session_id(),
            0,
            $params['path'],
            $params['domain'],
            true,
            $params['httponly'],
            false,
            Cookie::SAMESITE_LAX
        ));
    }

    public function onLogout(LogoutEvent $e): void
    {
        $response = $e->getResponse();

        if (null === $response) {
            return;
        }

        $this->doLogout($response);
    }

    private function doLogout(Response $response): void
    {
        if ($this->unsecuredLogout && null !== $response->headers->get('Location')) {
            $location = $response->headers->get('Location');
            $response->headers->set('Location', preg_replace('/^https/', 'http', $location));
        }

        $response->headers->clearCookie($this->cookieName);
    }
}
