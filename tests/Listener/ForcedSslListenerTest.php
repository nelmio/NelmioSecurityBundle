<?php

/*
 * This file is part of the Nelmio SecurityBundle.
 *
 * (c) Nelmio <hello@nelm.io>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Nelmio\SecurityBundle\Tests\Listener;

use Nelmio\SecurityBundle\EventListener\ForcedSslListener;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;

class ForcedSslListenerTest extends \PHPUnit\Framework\TestCase
{
    private $kernel;

    protected function setUp(): void
    {
        $this->kernel = $this->getMockBuilder(HttpKernelInterface::class)->getMock();
    }

    /**
     * @dataProvider provideHstsHeaders
     */
    public function testHstsHeaders($hstsMaxAge, $hstsSubdomains, $hstsPreload, $result)
    {
        $listener = new ForcedSslListener($hstsMaxAge, $hstsSubdomains, $hstsPreload);

        $response = $this->callListenerResp($listener, 'https://localhost/', true);
        $this->assertSame($result, $response->headers->get('Strict-Transport-Security'));
    }

    /**
     * @dataProvider provideHstsHeaders
     */
    public function testHstsHeadersNotSetForNonSecureRequest($hstsMaxAge, $hstsSubdomains, $hstsPreload)
    {
        $listener = new ForcedSslListener($hstsMaxAge, $hstsSubdomains, $hstsPreload);

        $response = $this->callListenerResp($listener, 'http://localhost/', true);
        $this->assertNull($response->headers->get('Strict-Transport-Security'));
    }

    public function provideHstsHeaders()
    {
        return [
            [60, true, false, 'max-age=60; includeSubDomains'],
            [60, false, false, 'max-age=60'],
            [3600, true, false, 'max-age=3600; includeSubDomains'],
            [3600, false, false, 'max-age=3600'],
            [3600, true, true, 'max-age=3600; includeSubDomains; preload'],
            [3600, false, true, 'max-age=3600; preload'],
        ];
    }

    public function testForcedSslSkipsSubReqs()
    {
        $listener = new ForcedSslListener(60, true);

        $response = $this->callListenerResp($listener, 'https://localhost/', false);
        $this->assertNull($response->headers->get('Strict-Transport-Security'));
    }

    public function testForcedSslSkipsWhitelisted()
    {
        $listener = new ForcedSslListener(60, true, false, ['^/foo/', 'bar']);

        $response = $this->callListenerReq($listener, 'http://localhost/foo/lala', true);
        $this->assertNull($response);

        $response = $this->callListenerReq($listener, 'http://localhost/lala/foo/lala', true);
        $this->assertSame('https://localhost/lala/foo/lala', $response->headers->get('Location'));

        $response = $this->callListenerReq($listener, 'https://localhost/lala/abarb', true);
        $this->assertNull($response);
    }

    public function testForcedSslOnlyUsesHosts()
    {
        $listener = new ForcedSslListener(60, true, false, [], ['^foo\.com$', '\.example\.org$']);

        $response = $this->callListenerReq($listener, 'http://afoo.com/foo/lala', true);
        $this->assertNull($response);

        $response = $this->callListenerReq($listener, 'http://foo.com/foo/lala', true);
        $this->assertSame('https://foo.com/foo/lala', $response->headers->get('Location'));

        $response = $this->callListenerReq($listener, 'http://test.example.org/foo/lala', true);
        $this->assertSame('https://test.example.org/foo/lala', $response->headers->get('Location'));
    }

    public function testForcedSslRedirectStatusCodes()
    {
        $listener = new ForcedSslListener(null, false);

        $response = $this->callListenerReq($listener, '/foo/lala', true);
        $this->assertSame(302, $response->getStatusCode());

        $listener = new ForcedSslListener(null, false, false, [], [], 301);

        $response = $this->callListenerReq($listener, '/foo/lala', true);
        $this->assertSame(301, $response->getStatusCode());
    }

    protected function callListenerReq($listener, $uri, $masterReq)
    {
        $request = Request::create($uri);

        $event = new RequestEvent($this->kernel, $request, $masterReq ? HttpKernelInterface::MASTER_REQUEST : HttpKernelInterface::SUB_REQUEST);
        $listener->onKernelRequest($event);

        return $event->getResponse();
    }

    protected function callListenerResp(ForcedSslListener $listener, $uri, $masterReq)
    {
        $request = Request::create($uri);
        $response = new Response();

        $event = new ResponseEvent($this->kernel, $request, $masterReq ? HttpKernelInterface::MASTER_REQUEST : HttpKernelInterface::SUB_REQUEST, $response);
        $listener->onKernelResponse($event);

        return $response;
    }
}
