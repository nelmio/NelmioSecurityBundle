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
use Symfony\Component\HttpKernel\Event\FilterResponseEvent;
use Symfony\Component\HttpKernel\Event\GetResponseEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;

class ForcedSslListenerTest extends \PHPUnit_Framework_TestCase
{
    private $kernel;

    protected function setUp()
    {
        $this->kernel = $this->getMock('Symfony\Component\HttpKernel\HttpKernelInterface');
    }

    /**
     * @dataProvider provideHstsHeaders
     */
    public function testHstsHeaders($hstsMaxAge, $hstsSubdomains, $hstsPreload, $result)
    {
        $listener = new ForcedSslListener($hstsMaxAge, $hstsSubdomains, $hstsPreload);

        $response = $this->callListenerResp($listener, '/', true);
        $this->assertSame($result, $response->headers->get('Strict-Transport-Security'));
    }

    public function provideHstsHeaders()
    {
        return array(
            array(60, true, false, 'max-age=60; includeSubDomains'),
            array(60, false, false, 'max-age=60'),
            array(3600, true, false, 'max-age=3600; includeSubDomains'),
            array(3600, false, false, 'max-age=3600'),
            array(3600, true, true, 'max-age=3600; includeSubDomains; preload'),
            array(3600, false, true, 'max-age=3600; preload'),
        );
    }

    public function testForcedSslSkipsSubReqs()
    {
        $listener = new ForcedSslListener(60, true);

        $response = $this->callListenerResp($listener, '/', false);
        $this->assertSame(null, $response->headers->get('Strict-Transport-Security'));
    }

    public function testForcedSslSkipsWhitelisted()
    {
        $listener = new ForcedSslListener(60, true, false, array('^/foo/', 'bar'));

        $response = $this->callListenerReq($listener, '/foo/lala', true);
        $this->assertSame(null, $response);

        $response = $this->callListenerReq($listener, '/lala/foo/lala', true);
        $this->assertSame('https://localhost/lala/foo/lala', $response->headers->get('Location'));

        $response = $this->callListenerReq($listener, '/lala/abarb', true);
        $this->assertSame(null, $response);
    }

    public function testForcedSslOnlyUsesHosts()
    {
        $listener = new ForcedSslListener(60, true, false, array(), array('^foo\.com$', '\.example\.org$'));

        $response = $this->callListenerReq($listener, 'http://afoo.com/foo/lala', true);
        $this->assertSame(null, $response);

        $response = $this->callListenerReq($listener, 'http://foo.com/foo/lala', true);
        $this->assertSame('https://foo.com/foo/lala', $response->headers->get('Location'));

        $response = $this->callListenerReq($listener, 'http://test.example.org/foo/lala', true);
        $this->assertSame('https://test.example.org/foo/lala', $response->headers->get('Location'));
    }

    public function testXForwardedProtoRedirectsIfHeaderIsNotPresent()
    {
        $listener = new ForcedSslListener(null, false, false, array(), array(), true);

        $response = $this->callListenerReq($listener, '/', true);
        $this->assertSame('https://localhost/', $response->headers->get('Location'));
    }

    public function testXForwardedProtoRedirectsIfHeaderIsPresentWithHTTPProtocol()
    {
        $listener = new ForcedSslListener(null, false, false, array(), array(), true);

        $request = Request::create('/');
        $request->headers->set('x-forwarded-proto', 'http');
        $event = new GetResponseEvent($this->kernel, $request, HttpKernelInterface::MASTER_REQUEST);
        $listener->onKernelRequest($event);
        $response = $event->getResponse();

        $this->assertSame('https://localhost/', $response->headers->get('Location'));
    }

    public function testXForwardedProtoSkipsRedirectIfHeaderIsPresent()
    {
        $listener = new ForcedSslListener(null, false, false, array(), array(), true);

        $request = Request::create('/');
        $request->headers->set('x-forwarded-proto', 'https');
        $event = new GetResponseEvent($this->kernel, $request, HttpKernelInterface::MASTER_REQUEST);
        $listener->onKernelRequest($event);
        $response = $event->getResponse();

        $this->assertNull($response);
    }

    protected function callListenerReq($listener, $path, $masterReq)
    {
        $request = Request::create($path);

        $event = new GetResponseEvent(
            $this->kernel,
            $request,
            $masterReq ? HttpKernelInterface::MASTER_REQUEST : HttpKernelInterface::SUB_REQUEST
        );
        $listener->onKernelRequest($event);

        return $event->getResponse();
    }

    protected function callListenerResp($listener, $path, $masterReq)
    {
        $request = Request::create($path);
        $response = new Response();

        $event = new FilterResponseEvent(
            $this->kernel,
            $request,
            $masterReq ? HttpKernelInterface::MASTER_REQUEST : HttpKernelInterface::SUB_REQUEST,
            $response
        );
        $listener->onKernelResponse($event);

        return $response;
    }
}
