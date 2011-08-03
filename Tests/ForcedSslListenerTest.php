<?php

/*
 * This file is part of the Nelmio SecurityBundle.
 *
 * (c) Nelmio <hello@nelm.io>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Nelmio\SecurityBundle\Tests;

use Nelmio\SecurityBundle\ForcedSslListener;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Symfony\Component\HttpKernel\Event\FilterResponseEvent;
use Symfony\Component\HttpKernel\KernelEvents;

class ForcedSslListenerTest extends \PHPUnit_Framework_TestCase
{
    private $kernel;

    protected function setUp()
    {
        $this->kernel = $this->getMock('Symfony\Component\HttpKernel\HttpKernelInterface');
    }

    public function testStstHeaders()
    {
        $listener = new ForcedSslListener(60, true);

        $response = $this->callListener($listener, '/', true);
        $this->assertContains('max-age=60', $response->headers->get('Strict-Transport-Security'));
    }

    public function testStstHeadersWithSubdomains()
    {
        $listener = new ForcedSslListener(60, true);

        $response = $this->callListener($listener, '/', true);
        $this->assertContains('includeSubDomains', $response->headers->get('Strict-Transport-Security'));
    }

    public function testStstHeadersWithoutSubdomains()
    {
        $listener = new ForcedSslListener(60, false);

        $response = $this->callListener($listener, '/', true);
        $this->assertNotContains('includeSubDomains', $response->headers->get('Strict-Transport-Security'));
    }

    public function testForcedSslSkipsSubReqs()
    {
        $listener = new ForcedSslListener(60, true);

        $response = $this->callListener($listener, '/', false);
        $this->assertSame(null, $response->headers->get('Strict-Transport-Security'));
    }

    protected function callListener($listener, $path, $masterReq)
    {
        $request = Request::create($path);
        $response = new Response();

        $event = new FilterResponseEvent($this->kernel, $request, $masterReq ? HttpKernelInterface::MASTER_REQUEST : HttpKernelInterface::SUB_REQUEST, $response);
        $listener->onKernelResponse($event);

        return $response;
    }
}
