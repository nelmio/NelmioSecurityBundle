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

namespace Nelmio\SecurityBundle\Tests\Session;

use Nelmio\SecurityBundle\Session\CookieSessionHandler;
use Nelmio\SecurityBundle\Tests\Listener\ListenerTestCase;
use PHPUnit\Framework\MockObject\Stub;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\ResponseHeaderBag;
use Symfony\Component\HttpFoundation\Session\SessionInterface;
use Symfony\Component\HttpKernel\HttpKernelInterface;

class CookieSessionHandlerTest extends ListenerTestCase
{
    private CookieSessionHandler $handler;

    /**
     * @var Stub&HttpKernelInterface
     */
    private $kernel;

    protected function setUp(): void
    {
        $this->handler = new CookieSessionHandler('s');

        $this->kernel = $this->createStub(HttpKernelInterface::class);
    }

    public function testOpenWithNoRequest(): void
    {
        $this->expectException('RuntimeException');

        $this->handler->open('foo', 'bar');
    }

    public function testReadWithNoRequest(): void
    {
        $this->expectException('RuntimeException');

        $this->handler->read('foo');
    }

    public function testOpenWithoutSessionCookie(): void
    {
        $request = new Request();
        $response = new Response();
        $session = $this->getMockBuilder(SessionInterface::class)->getMock();
        $session->expects($this->once())->method('save');
        $request->setSession($session);

        $this->handler->onKernelRequest($this->createRequestEventWithKernel($this->kernel, $request, true));

        $this->assertTrue($this->handler->open('foo', 'bar'));

        $this->handler->write('sessionId', 'mydata');

        $this->handler->onKernelResponse($this->createResponseEventWithKernel($this->kernel, $request, true, $response));

        $cookies = $response->headers->getCookies();

        $this->assertCount(1, $cookies);
        $this->assertSame('a:2:{s:6:"expire";i:0;s:4:"data";s:6:"mydata";}', $cookies[0]->getValue());
        $this->assertSame('s', $cookies[0]->getName());
    }

    public function testWriteDestroy(): void
    {
        $this->handler->write('sessionId', 'mydata');

        $request = new Request();
        $response = new Response();
        $session = $this->getMockBuilder(SessionInterface::class)->getMock();
        $session->expects($this->exactly(2))->method('save');
        $request->setSession($session);

        $this->handler->onKernelRequest($this->createRequestEventWithKernel($this->kernel, $request, true));

        $this->handler->onKernelResponse($this->createResponseEventWithKernel($this->kernel, $request, true, $response));

        $cookies = $response->headers->getCookies();

        $this->assertCount(1, $cookies);
        $this->assertSame('a:2:{s:6:"expire";i:0;s:4:"data";s:6:"mydata";}', $cookies[0]->getValue());
        $this->assertSame('s', $cookies[0]->getName());

        $this->handler->destroy('sessionId');

        $this->handler->onKernelResponse($this->createResponseEventWithKernel($this->kernel, $request, true, $response));

        $cookies = $response->headers->getCookies();

        $this->assertCount(1, $cookies);
        $this->assertNull($cookies[0]->getValue());
        $this->assertSame('s', $cookies[0]->getName());
    }

    /**
     * Cookie not opened.
     */
    public function testCookieNotOpened(): void
    {
        $session = $this->createMock(SessionInterface::class);
        $headers = $this->createMock(ResponseHeaderBag::class);
        $headers
            ->method('clearCookie');
        $headers
            ->method('setCookie');

        $response = new Response();
        $request = new Request();
        $request->setSession($session);
        $response->headers = $headers;

        $this->handler->onKernelRequest($this->createRequestEventWithKernel($this->kernel, $request, true));

        $this->handler->onKernelResponse($this->createResponseEventWithKernel($this->kernel, $request, true, $response));

        $getCookie = \Closure::bind(static function (CookieSessionHandler $handler) {
            return $handler->cookie;
        }, null, CookieSessionHandler::class);

        $this->assertFalse($getCookie($this->handler));
    }
}
