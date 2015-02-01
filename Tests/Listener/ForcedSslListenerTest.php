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
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Symfony\Component\HttpKernel\Event\FilterResponseEvent;
use Symfony\Component\HttpKernel\Event\GetResponseEvent;

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

    protected function callListenerReq($listener, $path, $masterReq)
    {
        $request = Request::create($path);

        $event = new GetResponseEvent($this->kernel, $request, $masterReq ? HttpKernelInterface::MASTER_REQUEST : HttpKernelInterface::SUB_REQUEST);
        $listener->onKernelRequest($event);

        return $event->getResponse();
    }

    protected function callListenerResp($listener, $path, $masterReq)
    {
        $request = Request::create($path);
        $response = new Response();

        $event = new FilterResponseEvent($this->kernel, $request, $masterReq ? HttpKernelInterface::MASTER_REQUEST : HttpKernelInterface::SUB_REQUEST, $response);
        $listener->onKernelResponse($event);

        return $response;
    }
}
