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
use Symfony\Component\HttpKernel\Event\FilterResponseEvent;
use Symfony\Component\HttpKernel\Event\GetResponseEvent;

class ForcedSslListenerTest extends \PHPUnit\Framework\TestCase
{
    private $kernel;

    protected function setUp()
    {
        $this->kernel = $this->getMockBuilder('Symfony\Component\HttpKernel\HttpKernelInterface')->getMock();
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
        $this->assertSame(null, $response->headers->get('Strict-Transport-Security'));
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

        $response = $this->callListenerResp($listener, 'https://localhost/', false);
        $this->assertSame(null, $response->headers->get('Strict-Transport-Security'));
    }

    public function testForcedSslSkipsWhitelisted()
    {
        $listener = new ForcedSslListener(60, true, false, array('^/foo/', 'bar'));

        $response = $this->callListenerReq($listener, 'http://localhost/foo/lala', true);
        $this->assertSame(null, $response);

        $response = $this->callListenerReq($listener, 'http://localhost/lala/foo/lala', true);
        $this->assertSame('https://localhost/lala/foo/lala', $response->headers->get('Location'));

        $response = $this->callListenerReq($listener, 'https://localhost/lala/abarb', true);
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

    public function testForcedSslRedirectStatusCodes()
    {
        $listener = new ForcedSslListener(null, false);

        $response = $this->callListenerReq($listener, '/foo/lala', true);
        $this->assertSame(302, $response->getStatusCode());

        $listener = new ForcedSslListener(null, false, false, array(), array(), 301);

        $response = $this->callListenerReq($listener, '/foo/lala', true);
        $this->assertSame(301, $response->getStatusCode());
    }

    protected function callListenerReq($listener, $uri, $masterReq)
    {
        $request = Request::create($uri);

        if (class_exists(RequestEvent::class)) {
            $class = RequestEvent::class;
        } else {
            $class = GetResponseEvent::class;
        }

        $event = new $class($this->kernel, $request, $masterReq ? HttpKernelInterface::MASTER_REQUEST : HttpKernelInterface::SUB_REQUEST);
        $listener->onKernelRequest($event);

        return $event->getResponse();
    }

    protected function callListenerResp(ForcedSslListener $listener, $uri, $masterReq)
    {
        $request = Request::create($uri);
        $response = new Response();

        if (class_exists(ResponseEvent::class)) {
            $class = ResponseEvent::class;
        } else {
            $class = FilterResponseEvent::class;
        }

        $event = new $class($this->kernel, $request, $masterReq ? HttpKernelInterface::MASTER_REQUEST : HttpKernelInterface::SUB_REQUEST, $response);
        $listener->onKernelResponse($event);

        return $response;
    }
}
