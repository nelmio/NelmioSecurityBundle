<?php

namespace Nelmio\SecurityBundle\Tests\Listener;

use Nelmio\SecurityBundle\EventListener\ContentTypeListener;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\FilterResponseEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;

class ContentTypeListenerTest extends \PHPUnit_Framework_TestCase
{
    private $kernel;

    protected function setUp()
    {
        $this->kernel = $this->getMock('Symfony\Component\HttpKernel\HttpKernelInterface');
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

        $event = new FilterResponseEvent($this->kernel, $request, $masterReq ? HttpKernelInterface::MASTER_REQUEST : HttpKernelInterface::SUB_REQUEST, $response);
        $listener->onKernelResponse($event);

        return $response;
    }
}
