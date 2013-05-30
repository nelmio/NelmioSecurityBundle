<?php

namespace Nelmio\SecurityBundle\Tests\Listener;

use Nelmio\SecurityBundle\EventListener\ContentSecurityPolicyListener;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\FilterResponseEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;

class ContentSecurityPolicyListenerTest extends \PHPUnit_Framework_TestCase
{
    private $kernel;

    protected function setUp()
    {
        $this->kernel = $this->getMock('Symfony\Component\HttpKernel\HttpKernelInterface');
    }

    public function testDefault()
    {
        $default = array(
            'hostname',
            'self',
            'https://example.com',
            'hostname:8080'
        );

        $listener = new ContentSecurityPolicyListener($default);
        $response = $this->callListener($listener, '/', true);

        $this->assertEquals("default-src hostname 'self' https://example.com hostname:8080", $response->headers->get('Content-Security-Policy'));
    }

    protected function callListener(ContentSecurityPolicyListener $listener, $path, $masterReq)
    {
        $request  = Request::create($path);
        $response = new Response();

        $event = new FilterResponseEvent($this->kernel, $request, $masterReq ? HttpKernelInterface::MASTER_REQUEST : HttpKernelInterface::SUB_REQUEST, $response);
        $listener->onKernelResponse($event);

        return $response;
    }
}