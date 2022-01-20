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
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\Exception\HttpException;
use Symfony\Component\HttpKernel\HttpKernelInterface;

class ExternalRedirectListenerTest extends \PHPUnit\Framework\TestCase
{
    private $kernel;

    protected function setUp(): void
    {
        $this->kernel = $this->getMockBuilder(HttpKernelInterface::class)->getMock();
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
        return [
            // internal
            ['http://test.org/', 'http://test.org/foo', false],
            ['http://test.org/', 'https://test.org/foo', false],
            ['http://test.org/', '/foo', false],
            ['http://test.org/', 'foo', false],

            // external
            ['http://test.org/', 'http://example.org/foo', true],
            ['http://test.org/', 'http://foo.test.org/', true],
            ['http://test.org/', 'http://test.org.com/', true],
            ['http://test.org/', 'http://foo.com/http://test.org/', true],
            ['http://test.org/', '//foo.com/', true],
            ['http://test.org/', "\r".'http://foo.com/', true],
            ['http://test.org/', "\0\0".'http://foo.com/', true],
            ['http://test.org/', '  '.'http://foo.com/', true],
        ];
    }

    /**
     * @depends testRedirectMatcher
     */
    public function testRedirectAbort()
    {
        $this->expectException(HttpException::class);

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
        $listener = new ExternalRedirectListener(true, null, null, new WhitelistBasedTargetValidator(['bar.com']));

        $response = $this->filterResponse($listener, 'http://foo.com/', 'http://bar.com');
        $this->assertTrue($response->isRedirect());
    }

    /**
     * @depends testRedirectMatcher
     * @dataProvider provideRedirectWhitelistsFailing
     */
    public function testRedirectDoesNotSkipNonWhitelistedDomains($whitelist, $domain)
    {
        $this->expectException(HttpException::class);

        $listener = new ExternalRedirectListener(true, null, null, $whitelist);

        $this->filterResponse($listener, 'http://foo.com/', 'http://'.$domain.'/');
    }

    public function provideRedirectWhitelistsFailing()
    {
        return [
            [['bar.com', 'baz.com'], 'abaz.com'],
            [['bar.com', 'baz.com'], 'moo.com'],
            [['.co.uk'], 'telco.uk'],
            [[], 'bar.com'],
        ];
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
        return [
            [['bar.com', 'baz.com'], 'bar.com'],
            [['bar.com', 'baz.com'], '.baz.com'],
            [['bar.com', 'baz.com'], 'foo.baz.com'],
            [['.co.uk'], 'tel.co.uk'],
            [[], ''],
        ];
    }

    public function testListenerSkipsSubReqs()
    {
        $listener = new ExternalRedirectListener(true);
        $request = Request::create('http://test.org/');

        $response = new RedirectResponse('http://foo.com/');

        if (class_exists(ResponseEvent::class)) {
            $class = ResponseEvent::class;
        } else {
            $class = 'Symfony\Component\HttpKernel\Event\FilterResponseEvent';
        }

        $event = new $class($this->kernel, $request, HttpKernelInterface::SUB_REQUEST, $response);
        $listener->onKernelResponse($event);

        $this->assertSame(true, $response->isRedirect());
        $this->assertSame('http://foo.com/', $response->headers->get('Location'));
    }

    protected function filterResponse($listener, $source, $target)
    {
        $request = Request::create($source);

        $response = new RedirectResponse($target);

        if (class_exists(ResponseEvent::class)) {
            $class = ResponseEvent::class;
        } else {
            $class = 'Symfony\Component\HttpKernel\Event\FilterResponseEvent';
        }

        $event = new $class($this->kernel, $request, HttpKernelInterface::MASTER_REQUEST, $response);
        $listener->onKernelResponse($event);

        return $response;
    }
}
