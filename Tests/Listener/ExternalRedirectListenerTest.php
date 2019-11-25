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

use Nelmio\SecurityBundle\EventListener\ExternalRedirectListener;
use Nelmio\SecurityBundle\ExternalRedirect\WhitelistBasedTargetValidator;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Symfony\Component\HttpKernel\Event\FilterResponseEvent;

class ExternalRedirectListenerTest extends \PHPUnit\Framework\TestCase
{
    private $kernel;

    protected function setUp(): void
    {
        $this->kernel = $this->getMockBuilder('Symfony\Component\HttpKernel\HttpKernelInterface')->getMock();
    }

    /**
     * @dataProvider provideRedirectMatcher
     */
    public function testRedirectMatcher($source, $target, $expected)
    {
        $listener = new ExternalRedirectListener(true);
        $result = $listener->isExternalRedirect($source, $target);
        $this->assertSame($expected, $result);
    }

    public function provideRedirectMatcher()
    {
        return array(
            // internal
            array('http://test.org/', 'http://test.org/foo', false),
            array('http://test.org/', 'https://test.org/foo', false),
            array('http://test.org/', '/foo', false),
            array('http://test.org/', 'foo', false),

            // external
            array('http://test.org/', 'http://example.org/foo', true),
            array('http://test.org/', 'http://foo.test.org/', true),
            array('http://test.org/', 'http://test.org.com/', true),
            array('http://test.org/', 'http://foo.com/http://test.org/', true),
            array('http://test.org/', '//foo.com/', true),
            array('http://test.org/', "\r".'http://foo.com/', true),
            array('http://test.org/', "\0\0".'http://foo.com/', true),
            array('http://test.org/', "  ".'http://foo.com/', true),
        );
    }

    /**
     * @depends testRedirectMatcher
     * @expectedException Symfony\Component\HttpKernel\Exception\HttpException
     */
    public function testRedirectAbort()
    {
        $listener = new ExternalRedirectListener(true);
        $this->filterResponse($listener, 'http://foo.com/', 'http://bar.com/');
    }

    /**
     * @depends testRedirectMatcher
     */
    public function testRedirectOverrides()
    {
        $listener = new ExternalRedirectListener(false, '/override');
        $response = $this->filterResponse($listener, 'http://foo.com/', 'http://bar.com/');

        $this->assertSame(true, $response->isRedirect());
        $this->assertSame('/override', $response->headers->get('Location'));
    }

    /**
     * @depends testRedirectMatcher
     */
    public function testRedirectSkipsAllowedTargets()
    {
        $listener = new ExternalRedirectListener(true, null, null, new WhitelistBasedTargetValidator(array('bar.com')));

        $response = $this->filterResponse($listener, 'http://foo.com/', 'http://bar.com');
        $this->assertTrue($response->isRedirect());
    }

    /**
     * @depends testRedirectMatcher
     * @dataProvider provideRedirectWhitelistsFailing
     * @expectedException Symfony\Component\HttpKernel\Exception\HttpException
     */
    public function testRedirectDoesNotSkipNonWhitelistedDomains($whitelist, $domain)
    {
        $listener = new ExternalRedirectListener(true, null, null, $whitelist);

        $this->filterResponse($listener, 'http://foo.com/', 'http://'.$domain.'/');
    }

    public function provideRedirectWhitelistsFailing()
    {
        return array(
            array(array('bar.com', 'baz.com'), 'abaz.com'),
            array(array('bar.com', 'baz.com'), 'moo.com'),
            array(array('.co.uk'), 'telco.uk'),
            array(array(), 'bar.com'),
        );
    }

    /**
     * @depends testRedirectMatcher
     * @dataProvider provideRedirectWhitelistsPassing
     */
    public function testRedirectSkipsWhitelistedDomains($whitelist, $domain)
    {
        $listener = new ExternalRedirectListener(true, null, null, $whitelist);

        $response = $this->filterResponse($listener, 'http://foo.com/', 'http://'.$domain.'/');

        $this->assertTrue($response->isRedirect());
    }

    public function provideRedirectWhitelistsPassing()
    {
        return array(
            array(array('bar.com', 'baz.com'), 'bar.com'),
            array(array('bar.com', 'baz.com'), '.baz.com'),
            array(array('bar.com', 'baz.com'), 'foo.baz.com'),
            array(array('.co.uk'), 'tel.co.uk'),
            array(array(), ''),
        );
    }

    public function testListenerSkipsSubReqs()
    {
        $listener = new ExternalRedirectListener(true);
        $request = Request::create('http://test.org/');

        $response = new RedirectResponse('http://foo.com/');

        $event = new FilterResponseEvent($this->kernel, $request, HttpKernelInterface::SUB_REQUEST, $response);
        $listener->onKernelResponse($event);

        $this->assertSame(true, $response->isRedirect());
        $this->assertSame('http://foo.com/', $response->headers->get('Location'));
    }

    protected function filterResponse($listener, $source, $target)
    {
        $request = Request::create($source);

        $response = new RedirectResponse($target);

        $event = new FilterResponseEvent($this->kernel, $request, HttpKernelInterface::MASTER_REQUEST, $response);
        $listener->onKernelResponse($event);

        return $response;
    }
}
