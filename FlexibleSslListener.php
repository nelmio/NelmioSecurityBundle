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

use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\ResponseHeaderBag;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpKernel\Event\GetResponseEvent;
use Symfony\Component\HttpKernel\Event\FilterResponseEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Symfony\Component\Security\Http\Event\InteractiveLoginEvent;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Http\Logout\LogoutHandlerInterface;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;

class FlexibleSslListener implements LogoutHandlerInterface
{
    private $cookieName;
    private $dispatcher;

    public function __construct($cookieName, EventDispatcherInterface $dispatcher)
    {
        $this->cookieName = $cookieName;
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

        $request = $e->getRequest();
        $response = $e->getResponse();

        if ($request->attributes->has(RememberMeServicesInterface::COOKIE_ATTR_NAME)) {
            $rememberMeCookie = $request->attributes->get(RememberMeServicesInterface::COOKIE_ATTR_NAME);
        }

        // set the auth cookie
        if ('1' !== $e->getRequest()->cookies->get($this->cookieName)) {
            $expiration = isset($rememberMeCookie) ? $rememberMeCookie->getExpiresTime() : 0;
            $response->headers->setCookie(new Cookie($this->cookieName, '1', $expiration));
        }

        // force remember-me cookie to be secure
        if (isset($rememberMeCookie) && !$rememberMeCookie->isSecure()) {
            $response->headers->setCookie(new Cookie(
                $rememberMeCookie->getName(),
                $rememberMeCookie->getValue(),
                $rememberMeCookie->getExpiresTime(),
                $rememberMeCookie->getPath(),
                $rememberMeCookie->getDomain(),
                true,
                $rememberMeCookie->isHttpOnly()
            ));
        }

        // force session cookie to be secure
        $params = session_get_cookie_params();
        $response->headers->setCookie(new Cookie(
            session_name(),
            session_id(),
            $params['lifetime'],
            $params['path'],
            $params['domain'],
            $params['secure'],
            $params['httponly']
        ));
    }

    // TODO this needs to be hooked into LogoutListener::addHandler of every firewall (security.logout_listener.*)
    public function logout(Request $request, Response $response, TokenInterface $token)
    {
        $response->headers->clearCookie($this->cookieName);
    }
}
