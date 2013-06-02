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
        $default = "hostname 'self'";

        $listener = new ContentSecurityPolicyListener($default);
        $response = $this->callListener($listener, '/', true);

        $this->assertEquals("default-src hostname 'self'", $response->headers->get('Content-Security-Policy'));
    }

    public function testScript()
    {
        $script = "hostname 'self' 'unsafe-eval' 'unsafe-inline'";

        $listener = new ContentSecurityPolicyListener(null, $script);
        $response = $this->callListener($listener, '/', true);
        $this->assertEquals(
            "script-src hostname 'self' 'unsafe-eval' 'unsafe-inline'",
            $response->headers->get('Content-Security-Policy')
        );
    }

    public function testObject()
    {
        $object = "hostname 'self'";

        $listener = new ContentSecurityPolicyListener(null, null, $object);
        $response = $this->callListener($listener, '/', true);
        $this->assertEquals("object-src hostname 'self'", $response->headers->get('Content-Security-Policy'));
    }

    public function testStyle()
    {
        $style = "hostname 'self'";

        $listener = new ContentSecurityPolicyListener(null, null, null, $style);
        $response = $this->callListener($listener, '/', true);
        $this->assertEquals("style-src hostname 'self'", $response->headers->get('Content-Security-Policy'));
    }

    public function testImg()
    {
        $img = "hostname 'self'";

        $listener = new ContentSecurityPolicyListener(null, null, null, null, $img);
        $response = $this->callListener($listener, '/', true);
        $this->assertEquals("img-src hostname 'self'", $response->headers->get('Content-Security-Policy'));
    }

    public function testMedia()
    {
        $media = "hostname 'self'";

        $listener = new ContentSecurityPolicyListener(null, null, null, null, null, $media);
        $response = $this->callListener($listener, '/', true);
        $this->assertEquals("media-src hostname 'self'", $response->headers->get('Content-Security-Policy'));
    }

    public function testFrame()
    {
        $frame = "hostname 'self'";

        $listener = new ContentSecurityPolicyListener(null, null, null, null, null, null, $frame);
        $response = $this->callListener($listener, '/', true);
        $this->assertEquals("frame-src hostname 'self'", $response->headers->get('Content-Security-Policy'));
    }

    public function testFont()
    {
        $font = "hostname 'self'";

        $listener = new ContentSecurityPolicyListener(null, null, null, null, null, null, null, $font);
        $response = $this->callListener($listener, '/', true);
        $this->assertEquals("font-src hostname 'self'", $response->headers->get('Content-Security-Policy'));
    }

    public function testConnect()
    {
        $connect = "hostname 'self'";

        $listener = new ContentSecurityPolicyListener(null, null, null, null, null, null, null, null, $connect);
        $response = $this->callListener($listener, '/', true);
        $this->assertEquals("connect-src hostname 'self'", $response->headers->get('Content-Security-Policy'));
    }

    public function testReportUri()
    {

    }

    protected function callListener(ContentSecurityPolicyListener $listener, $path, $masterReq)
    {
        $request = Request::create($path);
        $response = new Response();

        $event = new FilterResponseEvent($this->kernel, $request, $masterReq ? HttpKernelInterface::MASTER_REQUEST : HttpKernelInterface::SUB_REQUEST, $response);
        $listener->onKernelResponse($event);

        return $response;
    }
}