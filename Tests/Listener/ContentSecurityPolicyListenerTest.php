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

    public function testEmpty()
    {
        $listener = new ContentSecurityPolicyListener();
        $response = $this->callListener($listener, '/', true);
        $this->assertNull($response->headers->get('Content-Security-Policy'));
    }

    public function testAll()
    {
        $spec     = "hostname 'self'";
        $listener = new ContentSecurityPolicyListener($spec, $spec, $spec, $spec, $spec, $spec, $spec, $spec, $spec);
        $response = $this->callListener($listener, '/', true);

        $header = $response->headers->get('Content-Security-Policy');

        $this->assertContains("default-src hostname 'self'", $header, 'Header should contain default-src');
        $this->assertContains("script-src hostname 'self'", $header, 'Header should contain script-src');
        $this->assertContains("object-src hostname 'self'", $header, 'Header should contain object-src');
        $this->assertContains("style-src hostname 'self'", $header, 'Header should contain style-src');
        $this->assertContains("img-src hostname 'self'", $header, 'Header should contain img-src');
        $this->assertContains("media-src hostname 'self'", $header, 'Header should contain media-src');
        $this->assertContains("frame-src hostname 'self'", $header, 'Header should contain frame-src');
        $this->assertContains("font-src hostname 'self'", $header, 'Header should contain font-src');
        $this->assertContains("connect-src hostname 'self'", $header, 'Header should contain connect-src');
    }

    public function testDelimiter()
    {
        $spec     = "hostname";
        $listener = new ContentSecurityPolicyListener($spec, $spec, $spec, $spec, $spec, $spec, $spec, $spec, $spec);
        $response = $this->callListener($listener, '/', true);

        $header = $response->headers->get('Content-Security-Policy');

        $this->assertRegExp(
            '/^((default|script|object|style|img|media|frame|font|connect)-src hostname;\s?){8}(default|script|object|style|img|media|frame|font|connect)-src hostname/',
            $header,
            'The header should contain all directives  separated by a semicolon'
        );

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