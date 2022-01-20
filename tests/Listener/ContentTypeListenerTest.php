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

use Nelmio\SecurityBundle\EventListener\ContentTypeListener;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;

class ContentTypeListenerTest extends \PHPUnit\Framework\TestCase
{
    private $kernel;

    protected function setUp()
    {
        $this->kernel = $this->getMockBuilder(HttpKernelInterface::class)->getMock();
    }

    public function testNoSniff()
    {
        $listener = new ContentTypeListener(true);
        $response = $this->callListener($listener, '/', true);
        $this->assertEquals(
            'nosniff',
            $response->headers->get('X-Content-Type-Options'),
            'X-Content-Type-Options header should be present'
        );
    }

    public function testEmpty()
    {
        $listener = new ContentTypeListener(false);
        $response = $this->callListener($listener, '/', true);
        $this->assertNull(
            $response->headers->get('X-Content-Type-Options'),
            'X-Content-Type-Options header should not be present'
        );
    }

    protected function callListener(ContentTypeListener $listener, $path, $masterReq)
    {
        $request = Request::create($path);
        $response = new Response();

        if (class_exists(ResponseEvent::class)) {
            $class = ResponseEvent::class;
        } else {
            $class = 'Symfony\Component\HttpKernel\Event\FilterResponseEvent';
        }

        $event = new $class($this->kernel, $request, $masterReq ? HttpKernelInterface::MASTER_REQUEST : HttpKernelInterface::SUB_REQUEST, $response);
        $listener->onKernelResponse($event);

        return $response;
    }
}
