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

use Nelmio\SecurityBundle\EventListener\SignedCookieUpgradeListener;
use Nelmio\SecurityBundle\SignedCookie\LegacySignatureCookieTracker;
use Nelmio\SecurityBundle\SignedCookie\UpgradedCookieBuilderInterface;
use PHPUnit\Framework\MockObject\Stub;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\ResponseHeaderBag;
use Symfony\Component\HttpKernel\HttpKernelInterface;

class SignedCookieUpgradeListenerTest extends ListenerTestCase
{
    /**
     * @var Stub&HttpKernelInterface
     */
    private $kernel;

    private LegacySignatureCookieTracker $tracker;

    protected function setUp(): void
    {
        $this->kernel = $this->createStub(HttpKernelInterface::class);

        $this->tracker = new LegacySignatureCookieTracker();
    }

    public function testSkipsSubRequests(): void
    {
        $this->tracker->flagForUpgrade('legacy');
        $listener = new SignedCookieUpgradeListener(
            $this->tracker,
            $this->createBuilder(Cookie::create('legacy', 'foobar_upgraded'))
        );

        $request = Request::create('/', Request::METHOD_GET, [], ['legacy' => 'foobar']);
        $response = new Response();

        $event = $this->createResponseEventWithKernel($this->kernel, $request, false, $response);
        $listener->onKernelResponse($event);

        $this->assertEmpty($response->headers->getCookies());
    }

    public function testEligibleLegacyCookieIsCopiedToResponse(): void
    {
        $this->tracker->flagForUpgrade('legacy');
        $listener = new SignedCookieUpgradeListener(
            $this->tracker,
            $this->createBuilder(Cookie::create('legacy', 'foobar_upgraded'))
        );

        $request = Request::create('/', Request::METHOD_GET, [], ['legacy' => 'foobar']);
        $response = new Response();

        $event = $this->createResponseEventWithKernel($this->kernel, $request, true, $response);
        $listener->onKernelResponse($event);

        $cookies = $response->headers->getCookies(ResponseHeaderBag::COOKIES_ARRAY);
        $this->assertSame('foobar_upgraded', $cookies['']['/']['legacy']->getValue());
    }

    public function testIneligibleLegacyCookieIsNotCopiedToResponse(): void
    {
        $listener = new SignedCookieUpgradeListener(
            $this->tracker,
            $this->createBuilder(Cookie::create('legacy', 'foobar_upgraded'))
        );

        $request = Request::create('/', Request::METHOD_GET, [], ['legacy' => 'foobar']);
        $response = new Response();

        $event = $this->createResponseEventWithKernel($this->kernel, $request, true, $response);
        $listener->onKernelResponse($event);

        $this->assertEmpty($response->headers->getCookies());
    }

    public function testEligibleLegacyCookieIsIgnoredWhenNoBuilder(): void
    {
        $this->tracker->flagForUpgrade('legacy');
        $listener = new SignedCookieUpgradeListener($this->tracker, $this->createBuilder(null));

        $request = Request::create('/', Request::METHOD_GET, [], ['legacy' => 'foobar']);
        $response = new Response();

        $event = $this->createResponseEventWithKernel($this->kernel, $request, true, $response);
        $listener->onKernelResponse($event);

        $this->assertEmpty($response->headers->getCookies());
    }

    public function testExistingEligibleLegacyCookieIsIgnored(): void
    {
        $this->tracker->flagForUpgrade('legacy');
        $listener = new SignedCookieUpgradeListener(
            $this->tracker,
            $this->createBuilder(Cookie::create('legacy', 'foobar_upgraded'))
        );

        $request = Request::create('/', Request::METHOD_GET, [], ['legacy' => 'foobar']);
        $response = new Response();
        $response->headers->setCookie(Cookie::create('legacy', 'foobar_already_on_response'));

        $event = $this->createResponseEventWithKernel($this->kernel, $request, true, $response);
        $listener->onKernelResponse($event);

        $cookies = $response->headers->getCookies(ResponseHeaderBag::COOKIES_ARRAY);
        $this->assertSame('foobar_already_on_response', $cookies['']['/']['legacy']->getValue());
    }

    private function createBuilder(?Cookie $cookie): UpgradedCookieBuilderInterface
    {
        $mock = $this->createMock(UpgradedCookieBuilderInterface::class);

        if (null !== $cookie) {
            $mock->method('build')->willReturn($cookie);
        }

        return $mock;
    }
}
