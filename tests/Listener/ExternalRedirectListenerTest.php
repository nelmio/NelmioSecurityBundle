<?php

declare(strict_types=1);

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
use Nelmio\SecurityBundle\ExternalRedirect\AllowListBasedTargetValidator;
use Nelmio\SecurityBundle\ExternalRedirect\ExternalRedirectResponse;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Exception\HttpException;

class ExternalRedirectListenerTest extends ListenerTestCase
{
    /**
     * @dataProvider provideRedirectMatcher
     */
    public function testRedirectMatcher(string $source, string $target, bool $expected): void
    {
        $listener = new ExternalRedirectListener(true);
        $result = $listener->isExternalRedirect($source, $target);
        $this->assertSame($expected, $result);
    }

    public function provideRedirectMatcher(): array
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
            ['http://test.org/', '  http://foo.com/', true],
        ];
    }

    public function testRedirectAbort(): void
    {
        $this->expectException(HttpException::class);

        $listener = new ExternalRedirectListener(true);
        $this->filterResponse($listener, 'http://foo.com/', 'http://bar.com/');
    }

    /**
     * @dataProvider provideRedirectOverrides
     */
    public function testRedirectOverridesWithForwardAs(
        string $override,
        ?string $forwardAs,
        string $target,
        string $expected
    ): void {
        $listener = new ExternalRedirectListener(false, $override, $forwardAs);
        $response = $this->filterResponse($listener, 'http://foo.com/', $target);

        $this->assertTrue($response->isRedirect());
        $this->assertSame($expected, $response->headers->get('Location'));
    }

    public function provideRedirectOverrides(): iterable
    {
        $target = 'http://bar.com/';

        yield 'simple override' => [
            '/override',
            null,
            $target,
            '/override',
        ];

        yield 'with forwardAs' => [
            '/override',
            'redirect_to',
            $target,
            \sprintf('/override?redirect_to=%s', urlencode($target)),
        ];

        yield 'override with parameter and with forwardAs' => [
            '/override?param=value',
            'redirect_to',
            $target,
            \sprintf('/override?param=value&redirect_to=%s', urlencode($target)),
        ];
    }

    public function testRedirectSkipsAllowedTargets(): void
    {
        $listener = new ExternalRedirectListener(true, null, null, new AllowListBasedTargetValidator(['bar.com']));

        $response = $this->filterResponse($listener, 'http://foo.com/', 'http://bar.com');
        $this->assertTrue($response->isRedirect());
    }

    public function testExternalRedirectResponseSkipsAllowedTargets(): void
    {
        $listener = new ExternalRedirectListener(true, null, null, new AllowListBasedTargetValidator(['bar.com']));

        $response = $this->filterRedirectResponse($listener, 'http://foo.com/', 'http://allowed.com', ['allowed.com']);
        $this->assertTrue($response->isRedirect());
    }

    public function testExternalRedirectResponseSkipsGlobalAllowedTargets(): void
    {
        $listener = new ExternalRedirectListener(true, null, null, new AllowListBasedTargetValidator(['bar.com']));

        $response = $this->filterRedirectResponse($listener, 'http://foo.com/', 'http://bar.com', ['allowed.com']);
        $this->assertTrue($response->isRedirect());
    }

    public function testExternalRedirectResponseAborts(): void
    {
        $this->expectException(HttpException::class);
        $listener = new ExternalRedirectListener(true, null, null, new AllowListBasedTargetValidator(['bar.com']));

        $response = $this->filterRedirectResponse($listener, 'http://foo.com/', 'http://not-allowed.com', ['allowed.com']);
        $this->assertTrue($response->isRedirect());
    }

    /**
     * @dataProvider provideRedirectAllowedListFailing
     *
     * @param string[] $allowList
     */
    public function testRedirectDoesNotSkipNonAllowedDomains(array $allowList, string $domain): void
    {
        $this->expectException(HttpException::class);

        $listener = new ExternalRedirectListener(true, null, null, $allowList);

        $this->filterResponse($listener, 'http://foo.com/', 'http://'.$domain.'/');
    }

    public function provideRedirectAllowedListFailing(): array
    {
        return [
            [['bar.com', 'baz.com'], 'abaz.com'],
            [['bar.com', 'baz.com'], 'moo.com'],
            [['.co.uk'], 'telco.uk'],
            [[], 'bar.com'],
        ];
    }

    /**
     * @dataProvider provideRedirectAllowedListPassing
     *
     * @param string[] $allowList
     */
    public function testRedirectSkipsAllowedDomains(array $allowList, string $domain): void
    {
        $listener = new ExternalRedirectListener(true, null, null, $allowList);

        $response = $this->filterResponse($listener, 'http://foo.com/', 'http://'.$domain.'/');

        $this->assertTrue($response->isRedirect());
    }

    public function provideRedirectAllowedListPassing(): array
    {
        return [
            [['bar.com', 'baz.com'], 'bar.com'],
            [['bar.com', 'baz.com'], '.baz.com'],
            [['bar.com', 'baz.com'], 'foo.baz.com'],
            [['.co.uk'], 'tel.co.uk'],
            [[], ''],
        ];
    }

    public function testListenerSkipsSubReqs(): void
    {
        $listener = new ExternalRedirectListener(true);
        $request = Request::create('http://test.org/');

        $response = new RedirectResponse('http://foo.com/');

        $event = $this->createResponseEvent($request, false, $response);
        $listener->onKernelResponse($event);

        $this->assertTrue($response->isRedirect());
        $this->assertSame('http://foo.com/', $response->headers->get('Location'));
    }

    private function filterResponse(ExternalRedirectListener $listener, string $source, string $target): RedirectResponse
    {
        $request = Request::create($source);

        $response = new RedirectResponse($target);

        $event = $this->createResponseEvent($request, true, $response);
        $listener->onKernelResponse($event);

        return $response;
    }

    /**
     * @param string[] $allowedHosts
     */
    private function filterRedirectResponse(
        ExternalRedirectListener $listener,
        string $source,
        string $target,
        array $allowedHosts
    ): ExternalRedirectResponse {
        $request = Request::create($source);
        $response = new ExternalRedirectResponse($target, $allowedHosts);

        $event = $this->createResponseEvent($request, true, $response);
        $listener->onKernelResponse($event);

        return $response;
    }
}
