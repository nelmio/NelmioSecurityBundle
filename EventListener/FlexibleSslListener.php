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

use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpKernel\Event\GetResponseEvent;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\Event\FilterResponseEvent;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Http\Event\InteractiveLoginEvent;
use Symfony\Component\Security\Http\Event\LogoutEvent;
use Symfony\Component\Security\Http\Logout\LogoutHandlerInterface;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;

if (interface_exists('Symfony\Component\Security\Http\Logout\LogoutHandlerInterface')) {
    interface BaseFlexibleSslListener extends LogoutHandlerInterface
    {
    }
} else {
    interface BaseFlexibleSslListener
    {
    }
}

/**
 * @final
 */
class FlexibleSslListener implements BaseFlexibleSslListener
{
    private $cookieName;
    private $unsecuredLogout;
    private $dispatcher;

    public function __construct($cookieName, $unsecuredLogout, EventDispatcherInterface $dispatcher)
    {
        $this->cookieName = $cookieName;
        $this->unsecuredLogout = $unsecuredLogout;
        $this->dispatcher = $dispatcher;
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

        // force users to use ssl if the auth cookie is present
        if ('1' === $request->cookies->get($this->cookieName) && !$request->isSecure()) {
            $e->setResponse(new RedirectResponse('https://'.substr($request->getUri(), 7)));
        }
    }

    public function onLogin(InteractiveLoginEvent $e)
    {
        $this->dispatcher->addListener('kernel.response', array($this, 'onPostLoginKernelResponse'), -1000);
    }

    /**
     * @param FilterResponseEvent|ResponseEvent $e
     */
    public function onPostLoginKernelResponse($e)
    {
        // Compatibility with Symfony < 5 and Symfony >=5
        if (!$e instanceof FilterResponseEvent && !$e instanceof ResponseEvent) {
            throw new \InvalidArgumentException(\sprintf('Expected instance of type %s, %s given', \class_exists(ResponseEvent::class) ? ResponseEvent::class : FilterResponseEvent::class, \is_object($e) ? \get_class($e) : \gettype($e)));
        }

        if (HttpKernelInterface::MASTER_REQUEST !== $e->getRequestType()) {
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
                    method_exists($cookie, 'isRaw') ? $cookie->isRaw() : null,
                    method_exists($cookie, 'getSameSite') ? $cookie->getSameSite() : null
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
                defined('Cookie::SAMESITE_LAX') ? Cookie::SAMESITE_LAX : null
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
            defined('Cookie::SAMESITE_LAX') ? Cookie::SAMESITE_LAX : null
        ));
    }

    public function onLogout(LogoutEvent $e)
    {
        $this->logout($e->getRequest(), $e->getResponse(), $e->getToken());
    }

    /**
     * Legacy method called from deprecated/removed Symfony\Component\Security\Http\Logout\LogoutHandlerInterface
     */
    public function logout(Request $request, Response $response, TokenInterface $token)
    {
        if ($this->unsecuredLogout) {
            $location = $response->headers->get('Location');
            $response->headers->set('Location', preg_replace('/^https/', 'http', $location));
        }

        $response->headers->clearCookie($this->cookieName);
    }
}
