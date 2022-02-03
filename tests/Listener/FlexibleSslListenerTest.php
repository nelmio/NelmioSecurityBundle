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

namespace Nelmio\SecurityBundle\Tests\Listener;

use Nelmio\SecurityBundle\EventListener\FlexibleSslListener;
use PHPUnit\Framework\MockObject\Stub;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\ResponseHeaderBag;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;

class FlexibleSslListenerTest extends ListenerTestCase
{
    /**
     * @var Stub&HttpKernelInterface
     */
    private $kernel;

    /**
     * @var Stub&EventDispatcherInterface
     */
    private $dispatcher;
    private FlexibleSslListener $listener;

    protected function setUp(): void
    {
        $this->kernel = $this->createStub(HttpKernelInterface::class);
        $this->dispatcher = $this->createStub(EventDispatcherInterface::class);
        $this->listener = new FlexibleSslListener('auth', false, $this->dispatcher);
    }

    public function testKernelRequestWithNonAuthedNonSslRequest(): void
    {
        $request = Request::create('http://localhost/');

        $event = $this->createRequestEventWithKernel($this->kernel, $request, true);
        $this->listener->onKernelRequest($event);

        $this->assertFalse($event->hasResponse());
    }

    public function testKernelRequestWithAuthedNonSslRequest(): void
    {
        $request = Request::create('http://localhost/');
        $request->cookies->set('auth', '1');

        $event = $this->createRequestEventWithKernel($this->kernel, $request, true);
        $this->listener->onKernelRequest($event);

        $this->assertTrue($event->hasResponse());
        $this->assertInstanceOf(Response::class, $event->getResponse());
        $this->assertTrue($event->getResponse()->isRedirection());
    }

    public function testKernelRequestWithNonAuthedSslRequest(): void
    {
        $request = Request::create('https://localhost/');

        $event = $this->createRequestEventWithKernel($this->kernel, $request, true);
        $this->listener->onKernelRequest($event);

        $this->assertFalse($event->hasResponse());
    }

    public function testKernelRequestWithAuthedSslRequest(): void
    {
        $request = Request::create('https://localhost/');
        $request->cookies->set('auth', '1');

        $event = $this->createRequestEventWithKernel($this->kernel, $request, true);
        $this->listener->onKernelRequest($event);

        $this->assertFalse($event->hasResponse());
    }

    public function testPostLoginKernelResponse(): void
    {
        $request = Request::create('https://localhost/');

        $response = new Response();

        $event = $this->createResponseEventWithKernel($this->kernel, $request, true, $response);
        $this->listener->onPostLoginKernelResponse($event);

        $cookies = $response->headers->getCookies(ResponseHeaderBag::COOKIES_ARRAY);
        $this->assertTrue(isset($cookies['']['/']['auth']));
        $this->assertSame('1', $cookies['']['/']['auth']->getValue());
        $this->assertFalse($cookies['']['/']['auth']->isSecure());

        $this->assertTrue(isset($cookies['']['/'][session_name()]));
        $this->assertSame(session_id(), $cookies['']['/'][session_name()]->getValue());
        $this->assertTrue($cookies['']['/'][session_name()]->isSecure());
    }

    public function testPostLoginKernelResponseForceCookiesToBeSecure(): void
    {
        $request = Request::create('https://localhost/');

        $unsecureCookie = Cookie::create(
            'unsecure',
            'unsecure_value',
            100,
            '/',
            null,
            false
        );
        $response = new Response();
        $response->headers->setCookie($unsecureCookie);

        $event = $this->createResponseEventWithKernel($this->kernel, $request, true, $response);
        $this->listener->onPostLoginKernelResponse($event);

        $cookies = $response->headers->getCookies(ResponseHeaderBag::COOKIES_ARRAY);
        $this->assertTrue(isset($cookies['']['/']['unsecure']));
        $this->assertSame('unsecure_value', $cookies['']['/']['unsecure']->getValue());
        $this->assertTrue($cookies['']['/']['unsecure']->isSecure());
    }

    public function testKernelRequestSkipsSubReqs(): void
    {
        $request = Request::create('http://localhost/');
        $request->cookies->set('auth', '1');

        $event = $this->createRequestEventWithKernel($this->kernel, $request, false);
        $this->listener->onKernelRequest($event);

        $this->assertFalse($event->hasResponse());
    }

    public function testPostLoginKernelResponseSkipsSubReqs(): void
    {
        $request = Request::create('https://localhost/');

        $response = new Response();

        $event = $this->createResponseEventWithKernel($this->kernel, $request, false, $response);
        $this->listener->onPostLoginKernelResponse($event);

        $cookies = $response->headers->getCookies(ResponseHeaderBag::COOKIES_ARRAY);
        $this->assertFalse(isset($cookies['']['/']['auth']));
    }

    public function testSecureLogout(): void
    {
        $response = new RedirectResponse('https://foo');
        $request = $this->getMockBuilder(Request::class)->getMock();
        $token = $this->getMockBuilder(TokenInterface::class)->getMock();

        $this->listener->logout($request, $response, $token);

        $this->assertSame('https://foo', $response->headers->get('Location'));
    }

    public function testUnsecuredLogout(): void
    {
        $unsecuredLogoutListener = new FlexibleSslListener('auth', true, $this->dispatcher);

        $response = new RedirectResponse('https://foo');
        $request = $this->getMockBuilder(Request::class)->getMock();
        $token = $this->getMockBuilder(TokenInterface::class)->getMock();

        $unsecuredLogoutListener->logout($request, $response, $token);

        $this->assertSame('http://foo', $response->headers->get('Location'));
    }
}
