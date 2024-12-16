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

use Nelmio\SecurityBundle\EventListener\SignedCookieListener;
use Nelmio\SecurityBundle\SignedCookie\LegacySignatureCookieTrackerInterface;
use Nelmio\SecurityBundle\Signer;
use PHPUnit\Framework\MockObject\Stub;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\ResponseHeaderBag;
use Symfony\Component\HttpKernel\HttpKernelInterface;

class SignedCookieListenerTest extends ListenerTestCase
{
    private Signer $signer;

    /**
     * @var Stub&HttpKernelInterface
     */
    private $kernel;

    protected function setUp(): void
    {
        $this->signer = new Signer('secret', 'sha1', 'md5');
        $this->kernel = $this->createStub(HttpKernelInterface::class);
    }

    /**
     * @dataProvider provideCookieReading
     *
     * @param list<string>          $signedCookieNames
     * @param array<string, string> $inputCookies
     * @param array<string, string> $expectedCookies
     */
    public function testCookieReading(array $signedCookieNames, array $inputCookies, array $expectedCookies): void
    {
        $listener = new SignedCookieListener($this->signer, $signedCookieNames);
        $request = Request::create('/', 'GET', [], $inputCookies);

        $event = $this->createRequestEventWithKernel($this->kernel, $request, true);
        $listener->onKernelRequest($event);

        $this->assertSame($expectedCookies, $request->cookies->all());
    }

    public function provideCookieReading(): array
    {
        return [
            [[], [], []],
            [[], ['foo' => 'bar'], ['foo' => 'bar']],
            [['foo'], ['foo' => 'bar'], []],
            [['foo'], ['foo' => 'bar.ca3756f81d3728a023bdc8a622c0906f373b795e'], ['foo' => 'bar']],
            [['*'], ['foo' => 'bar.ca3756f81d3728a023bdc8a622c0906f373b795e'], ['foo' => 'bar']],
            [['*'], ['foo' => 'bar.ca3756f81d3728a023bdc8a622c0906f373b795d'], []],
            [['*'], ['foo' => '.25af6174a0fcecc4d346680a72b7ce644b9a88e8'], ['foo' => '']],
            [['*'], ['legacy' => 'bar.d42bb85e6f20b90034d986ad68501a2d'], ['legacy' => 'bar']],
            [['*'], ['legacy' => 'bar.d42bb85e6f20b90034d986ad68501a2a'], []],
        ];
    }

    /**
     * @dataProvider provideCookieWriting
     *
     * @param list<string>          $signedCookieNames
     * @param array<string, string> $inputCookies
     * @param array<string, string> $expectedCookies
     */
    public function testCookieWriting(array $signedCookieNames, array $inputCookies, array $expectedCookies): void
    {
        $listener = new SignedCookieListener($this->signer, $signedCookieNames);
        $request = Request::create('/');

        $response = new Response();
        foreach ($inputCookies as $name => $cookie) {
            $response->headers->setCookie(Cookie::create($name, $cookie));
        }

        $event = $this->createResponseEventWithKernel($this->kernel, $request, true, $response);
        $listener->onKernelResponse($event);

        $responseCookieValues = [];
        foreach ($response->headers->getCookies() as $cookie) {
            $responseCookieValues[$cookie->getName()] = $cookie->getValue();
        }

        $this->assertSame($expectedCookies, $responseCookieValues);
    }

    public function provideCookieWriting(): array
    {
        return [
            [[], [], []],
            [[], ['foo' => 'bar'], ['foo' => 'bar']],
            [['foo'], ['foo' => 'bar'], ['foo' => 'bar.ca3756f81d3728a023bdc8a622c0906f373b795e']],
            [['*'], ['foo' => 'bar'], ['foo' => 'bar.ca3756f81d3728a023bdc8a622c0906f373b795e']],
            [['*'], ['foo' => null], ['foo' => '.25af6174a0fcecc4d346680a72b7ce644b9a88e8']],
        ];
    }

    public function testCookieReadingSkipsSubReqs(): void
    {
        $listener = new SignedCookieListener($this->signer, ['*']);
        $request = Request::create('/', 'GET', [], ['foo' => 'bar']);

        $event = $this->createRequestEventWithKernel($this->kernel, $request, false);
        $listener->onKernelRequest($event);

        $this->assertSame('bar', $request->cookies->get('foo'));
    }

    public function testCookieWritingSkipsSubReqs(): void
    {
        $listener = new SignedCookieListener($this->signer, ['*']);
        $request = Request::create('/');

        $response = new Response();
        $response->headers->setCookie(Cookie::create('foo', 'bar'));

        $event = $this->createResponseEventWithKernel($this->kernel, $request, false, $response);
        $listener->onKernelResponse($event);

        $cookies = $response->headers->getCookies(ResponseHeaderBag::COOKIES_ARRAY);
        $this->assertSame('bar', $cookies['']['/']['foo']->getValue());
    }

    public function testTrackerIsClearedOnRequest(): void
    {
        $tracker = $this->createMock(LegacySignatureCookieTrackerInterface::class);
        $tracker->expects(self::once())
            ->method('clear');

        $listener = new SignedCookieListener($this->signer, ['*'], $tracker);
        $request = Request::create('/');

        $event = $this->createRequestEventWithKernel($this->kernel, $request, true);
        $listener->onKernelRequest($event);
    }

    public function testFlagsLegacyCookieForUpgrade(): void
    {
        $tracker = $this->createMock(LegacySignatureCookieTrackerInterface::class);
        $tracker->expects(self::once())
            ->method('flagForUpgrade')
            ->with('legacy');

        $listener = new SignedCookieListener($this->signer, ['*'], $tracker);
        $request = Request::create('/', Request::METHOD_GET, [], [
            'legacy' => 'bar.d42bb85e6f20b90034d986ad68501a2d',
            'foo' => 'bar.ca3756f81d3728a023bdc8a622c0906f373b795e',
        ]);

        $event = $this->createRequestEventWithKernel($this->kernel, $request, true);
        $listener->onKernelRequest($event);
    }
}
