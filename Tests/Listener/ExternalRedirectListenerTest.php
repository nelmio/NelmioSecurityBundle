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

class ExternalRedirectListenerTest extends \PHPUnit_Framework_TestCase
{
    private $kernel;

    protected function setUp()
    {
        $this->kernel = $this->getMock('Symfony\Component\HttpKernel\HttpKernelInterface');
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
     * @dataProvider provideRedirectWhitelists
     */
    public function testRedirectSkipsWhitelistedDomains($whitelist, $domain, $pass)
    {
        $listener = new ExternalRedirectListener(true, null, null, $whitelist);

        if (!$pass) {
            $this->setExpectedException('Symfony\Component\HttpKernel\Exception\HttpException');
        }

        $response = $this->filterResponse($listener, 'http://foo.com/', 'http://'.$domain.'/');

        $this->assertSame($pass, $response->isRedirect());
    }

    public function provideRedirectWhitelists()
    {
        return array(
            array(array('bar.com','baz.com'), 'bar.com', true),
            array(array('bar.com','baz.com'), '.baz.com', true),
            array(array('bar.com','baz.com'), 'abaz.com', false),
            array(array('bar.com','baz.com'), 'foo.baz.com', true),
            array(array('bar.com','baz.com'), 'moo.com', false),
            array(array('.co.uk'), 'telco.uk', false),
            array(array('.co.uk'), 'tel.co.uk', true),
            array(array(), 'bar.com', false),
            array(array(), '', true),
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
