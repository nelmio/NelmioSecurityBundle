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

use Nelmio\SecurityBundle\EventListener\XssProtectionListener;
use Symfony\Bridge\PhpUnit\ExpectDeprecationTrait;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * @group legacy
 */
class XssProtectionListenerTest extends ListenerTestCase
{
    use ExpectDeprecationTrait;

    /**
     * @dataProvider provideLegacyVariousConfigs
     */
    public function testLegacyVariousConfig(string $expectedValue, XssProtectionListener $listener): void
    {
        $response = $this->callListener($listener, '/', true);

        $this->assertSame($expectedValue, $response->headers->get('X-Xss-Protection'));
    }

    public function provideLegacyVariousConfigs(): array
    {
        return [
            ['0', new XssProtectionListener(false, false)],
            ['1', new XssProtectionListener(true, false)],
            ['0', new XssProtectionListener(false, true)],
            ['1; mode=block', new XssProtectionListener(true, true)],
            ['1; mode=block; report=https://report.com/endpoint', new XssProtectionListener(true, true, 'https://report.com/endpoint')],
        ];
    }

    public function testLegacyDoesNotHasHeaderOnRedirection(): void
    {
        $request = Request::create('/');
        $response = new RedirectResponse('/redirect');

        $listener = new XssProtectionListener(true, true);

        $event = $this->createResponseEvent(
            $request,
            true,
            $response
        );
        $listener->onKernelResponse($event);

        $this->assertFalse($response->headers->has('X-Xss-Protection'));
    }

    private function callListener(XssProtectionListener $listener, string $path, bool $mainReq): Response
    {
        $request = Request::create($path);
        $response = new Response();

        $event = $this->createResponseEvent(
            $request,
            $mainReq,
            $response
        );
        $listener->onKernelResponse($event);

        return $response;
    }
}
