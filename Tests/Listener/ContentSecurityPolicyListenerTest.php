<?php

namespace Nelmio\SecurityBundle\Tests\Listener;

use Nelmio\SecurityBundle\EventListener\ContentSecurityPolicyListener;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\FilterResponseEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Nelmio\SecurityBundle\ContentSecurityPolicy\DirectiveSet;

class ContentSecurityPolicyListenerTest extends \PHPUnit_Framework_TestCase
{
    private $kernel;

    protected function setUp()
    {
        $this->kernel = $this->getMock('Symfony\Component\HttpKernel\HttpKernelInterface');
    }

    public function testDefault()
    {
        $listener = $this->buildSimpleListener(array('default-src' => "default.example.org 'self'"));
        $response = $this->callListener($listener, '/', true);

        $this->assertEquals(
            "default-src default.example.org 'self'",
            $response->headers->get('Content-Security-Policy')
        );
    }

    public function testWithContentTypeRestriction()
    {
        $listener = $this->buildSimpleListener(array('default-src' => "default.example.org 'self'"), false, true, array('text/html'));
        $response = $this->callListener($listener, '/', true, 'application/json');

        $this->assertEquals(null, $response->headers->get('Content-Security-Policy'));
    }

    public function testScript()
    {
        $script = "script.example.org 'self' 'unsafe-eval' 'unsafe-inline'";

        $listener = $this->buildSimpleListener(array('script-src' => $script));
        $response = $this->callListener($listener, '/', true);
        $this->assertEquals(
            "script-src script.example.org 'self' 'unsafe-eval' 'unsafe-inline'",
            $response->headers->get('Content-Security-Policy')
        );
    }

    public function testObject()
    {
        $object = "object.example.org 'self'";

        $listener = $this->buildSimpleListener(array('object-src' => $object));
        $response = $this->callListener($listener, '/', true);
        $this->assertEquals("object-src object.example.org 'self'", $response->headers->get('Content-Security-Policy'));
    }

    public function testStyle()
    {
        $style = "style.example.org 'self'";

        $listener = $this->buildSimpleListener(array('style-src' => $style));
        $response = $this->callListener($listener, '/', true);
        $this->assertEquals("style-src style.example.org 'self'", $response->headers->get('Content-Security-Policy'));
    }

    public function testImg()
    {
        $img = "img.example.org 'self'";

        $listener = $this->buildSimpleListener(array('img-src' => $img));
        $response = $this->callListener($listener, '/', true);
        $this->assertEquals("img-src img.example.org 'self'", $response->headers->get('Content-Security-Policy'));
    }

    public function testMedia()
    {
        $media = "media.example.org 'self'";

        $listener = $this->buildSimpleListener(array('media-src' => $media));
        $response = $this->callListener($listener, '/', true);
        $this->assertEquals("media-src media.example.org 'self'", $response->headers->get('Content-Security-Policy'));
    }

    public function testFrame()
    {
        $frame = "frame.example.org 'self'";

        $listener = $this->buildSimpleListener(array('frame-src' => $frame));
        $response = $this->callListener($listener, '/', true);
        $this->assertEquals("frame-src frame.example.org 'self'", $response->headers->get('Content-Security-Policy'));
    }

    public function testFont()
    {
        $font = "font.example.org 'self'";

        $listener = $this->buildSimpleListener(array('font-src' => $font));
        $response = $this->callListener($listener, '/', true);
        $this->assertEquals("font-src font.example.org 'self'", $response->headers->get('Content-Security-Policy'));
    }

    public function testConnect()
    {
        $connect = "connect.example.org 'self'";

        $listener = $this->buildSimpleListener(array('connect-src' => $connect));
        $response = $this->callListener($listener, '/', true);
        $this->assertEquals(
            "connect-src connect.example.org 'self'",
            $response->headers->get('Content-Security-Policy')
        );
    }

    public function testReportUri()
    {
        $reportUri = 'http://example.org/CSPReport';

        $listener = $this->buildSimpleListener(array('report-uri' => $reportUri));
        $response = $this->callListener($listener, '/', true);
        $this->assertEquals(
            'report-uri http://example.org/CSPReport',
            $response->headers->get('Content-Security-Policy')
        );
    }

    public function testEmpty()
    {
        $listener = $this->buildSimpleListener(array());
        $response = $this->callListener($listener, '/', true);
        $this->assertNull($response->headers->get('Content-Security-Policy'));
    }

    public function testAll()
    {
        $reportUri = 'http://example.org/CSPReport';

        $listener = $this->buildSimpleListener(array(
            'default-src' => "example.org 'self'",
            'script-src' => "script.example.org 'self'",
            'object-src' => "object.example.org 'self'",
            'style-src' => "style.example.org 'self'",
            'img-src' => "img.example.org 'self'",
            'media-src' => "media.example.org 'self'",
            'frame-src' => "frame.example.org 'self'",
            'font-src' => "font.example.org 'self'",
            'connect-src' => "connect.example.org 'self'",
            'report-uri' => $reportUri
        ));
        $response = $this->callListener($listener, '/', true);

        $header = $response->headers->get('Content-Security-Policy');

        $this->assertContains("default-src example.org 'self'", $header, 'Header should contain default-src');
        $this->assertContains("script-src script.example.org 'self'", $header, 'Header should contain script-src');
        $this->assertContains("object-src object.example.org 'self'", $header, 'Header should contain object-src');
        $this->assertContains("style-src style.example.org 'self'", $header, 'Header should contain style-src');
        $this->assertContains("img-src img.example.org 'self'", $header, 'Header should contain img-src');
        $this->assertContains("media-src media.example.org 'self'", $header, 'Header should contain media-src');
        $this->assertContains("frame-src frame.example.org 'self'", $header, 'Header should contain frame-src');
        $this->assertContains("font-src font.example.org 'self'", $header, 'Header should contain font-src');
        $this->assertContains("connect-src connect.example.org 'self'", $header, 'Header should contain connect-src');
        $this->assertContains("report-uri http://example.org/CSPReport", $header, 'Header should contain report-uri');
    }

    public function testDelimiter()
    {
        $spec     = "example.org";
        $listener = $this->buildSimpleListener(array(
            'default-src' => "default.example.org 'self'",
            'script-src' => "script.example.org 'self'",
            'object-src' => "object.example.org 'self'",
            'style-src' => "style.example.org 'self'",
            'img-src' => "img.example.org 'self'",
            'media-src' => "media.example.org 'self'",
            'frame-src' => "frame.example.org 'self'",
            'font-src' => "font.example.org 'self'",
            'connect-src' => "connect.example.org 'self'",
        ));
        $response = $this->callListener($listener, '/', true);

        $header = $response->headers->get('Content-Security-Policy');

        $this->assertSame(
            "default-src default.example.org 'self'; script-src script.example.org 'self'; ".
            "object-src object.example.org 'self'; style-src style.example.org 'self'; ".
            "img-src img.example.org 'self'; media-src media.example.org 'self'; ".
            "frame-src frame.example.org 'self'; font-src font.example.org 'self'; ".
            "connect-src connect.example.org 'self'",
            $header,
            'The header should contain all directives separated by a semicolon'
        );
    }

    public function testAvoidDuplicates()
    {
        $spec     = "example.org";
        $listener = $this->buildSimpleListener(array(
            'default-src' => $spec,
            'script-src' => $spec,
            'object-src' => $spec,
            'style-src' => $spec,
            'img-src' => $spec,
            'media-src' => $spec,
            'frame-src' => $spec,
            'font-src' => $spec,
            'connect-src' => $spec
        ));
        $response = $this->callListener($listener, '/', true);

        $header = $response->headers->get('Content-Security-Policy');

        $this->assertEquals(
            'default-src example.org',
            $header,
            'Response should contain only the default as the others are equivalent'
        );
    }

    public function testVendorPrefixes()
    {
        $spec     = "example.org";
        $listener = $this->buildSimpleListener(array(
            'default-src' => $spec,
            'script-src' => $spec,
            'object-src' => $spec,
            'style-src' => $spec,
            'img-src' => $spec,
            'media-src' => $spec,
            'frame-src' => $spec,
            'font-src' => $spec,
            'connect-src' => $spec
        ));
        $response = $this->callListener($listener, '/', true);

        $this->assertEquals(
            $response->headers->get('Content-Security-Policy'),
            $response->headers->get('X-Content-Security-Policy'),
            'Response should contain non-standard X-Content-Security-Policy header'
        );
    }

    public function testReportOnly()
    {
        $spec     = "example.org";
        $listener = $this->buildSimpleListener(array(
            'default-src' => $spec,
            'script-src' => $spec,
            'object-src' => $spec,
            'style-src' => $spec,
            'img-src' => $spec,
            'media-src' => $spec,
            'frame-src' => $spec,
            'font-src' => $spec,
            'connect-src' => $spec
        ), true);
        $response = $this->callListener($listener, '/', true);

        $this->assertNull($response->headers->get('Content-Security-Policy'));
        $this->assertNotNull($response->headers->get('Content-Security-Policy-Report-Only'));
    }

    public function testNoCompatHeaders()
    {
        $spec     = "example.org";
        $listener = $this->buildSimpleListener(array(
            'default-src' => $spec,
            'script-src' => $spec,
            'object-src' => $spec,
            'style-src' => $spec,
            'img-src' => $spec,
            'media-src' => $spec,
            'frame-src' => $spec,
            'font-src' => $spec,
            'connect-src' => $spec
        ), false, false);
        $response = $this->callListener($listener, '/', true);

        $this->assertNull($response->headers->get('X-Content-Security-Policy'));
        $this->assertNotNull($response->headers->get('Content-Security-Policy'));
    }

    public function testDirectiveSetUnset()
    {
        $directiveSet = new DirectiveSet();
        $directiveSet->setDirectives(array('default-src' => 'foo'));
        $this->assertEquals('default-src foo', $directiveSet->buildHeaderValue());
        $directiveSet->setDirective('default-src', '');
        $this->assertEquals('', $directiveSet->buildHeaderValue());
    }

    protected function buildSimpleListener(array $directives, $reportOnly = false, $compatHeaders = true, $contentTypes = array())
    {
        $directiveSet = new DirectiveSet();
        $directiveSet->setDirectives($directives);

        if ($reportOnly) {
            return new ContentSecurityPolicyListener($directiveSet, new DirectiveSet(), $compatHeaders, $contentTypes);
        } else {
            return new ContentSecurityPolicyListener(new DirectiveSet(), $directiveSet, $compatHeaders, $contentTypes);
        }
    }

    protected function callListener(ContentSecurityPolicyListener $listener, $path, $masterReq, $contentType = 'text/html')
    {
        $request  = Request::create($path);
        $response = new Response();
        $response->headers->add(array('content-type' => $contentType));

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
