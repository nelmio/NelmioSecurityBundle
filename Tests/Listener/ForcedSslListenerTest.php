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
use Symfony\Component\HttpKernel\KernelEvents;

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
    public function testHstsHeaders($hstsMaxAge, $hstsSubdomains, $result)
    {
        $listener = new ForcedSslListener($hstsMaxAge, $hstsSubdomains);

        $response = $this->callListener($listener, '/', true);
        $this->assertSame($result, $response->headers->get('Strict-Transport-Security'));
    }

    public function provideHstsHeaders()
    {
        return array(
            array(60, true, 'max-age=60; includeSubDomains'),
            array(60, false, 'max-age=60'),
            array(3600, true, 'max-age=3600; includeSubDomains'),
            array(3600, false, 'max-age=3600'),
        );
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
