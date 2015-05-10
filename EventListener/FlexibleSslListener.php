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
use Symfony\Component\HttpKernel\Event\FilterResponseEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Symfony\Component\Security\Http\RememberMe\RememberMeServicesInterface;
use Symfony\Component\Security\Http\Event\InteractiveLoginEvent;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Http\Logout\LogoutHandlerInterface;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;

class FlexibleSslListener implements LogoutHandlerInterface
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

    public function onKernelRequest(GetResponseEvent $e)
    {
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

    public function onPostLoginKernelResponse(FilterResponseEvent $e)
    {
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
                    $cookie->isHttpOnly()
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
                false
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
            $params['httponly']
        ));
    }

    public function logout(Request $request, Response $response, TokenInterface $token)
    {
        if ($this->unsecuredLogout) {
            $location = $response->headers->get('Location');
            $response->headers->set('Location', preg_replace('/^https/', 'http', $location));
        }

        $response->headers->clearCookie($this->cookieName);
    }
}
