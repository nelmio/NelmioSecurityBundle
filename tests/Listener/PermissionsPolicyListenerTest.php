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

use Nelmio\SecurityBundle\EventListener\PermissionsPolicyListener;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

final class PermissionsPolicyListenerTest extends ListenerTestCase
{
    /**
     * @dataProvider provideVariousConfigs
     */
    public function testVariousConfig(?string $expectedValue, PermissionsPolicyListener $listener): void
    {
        $response = $this->callListener($listener, '/', true);

        $this->assertSame($expectedValue, $response->headers->get('Permissions-Policy'));
    }

    /**
     * @return iterable<int, array<null|string, PermissionsPolicyListener>>
     */
    public function provideVariousConfigs(): iterable
    {
        return [
            [null, new PermissionsPolicyListener([])],
            ['camera=()', new PermissionsPolicyListener(['camera' => []])],
            ['camera=(self)', new PermissionsPolicyListener(['camera' => ['self']])],
            ['camera=(*)', new PermissionsPolicyListener(['camera' => ['*']])],
            ['camera=(src)', new PermissionsPolicyListener(['camera' => ['src']])],
            ['camera=("https://example.com")', new PermissionsPolicyListener(['camera' => ['https://example.com']])],
            ['camera=(self "https://example.com")', new PermissionsPolicyListener(['camera' => ['self', 'https://example.com']])],
            ['camera=(), microphone=(self)', new PermissionsPolicyListener(['camera' => [], 'microphone' => ['self']])],
            ['camera=(self), microphone=(*), geolocation=()', new PermissionsPolicyListener(['camera' => ['self'], 'microphone' => ['*'], 'geolocation' => []])],
            ['encrypted-media=(self "https://cdn.example.com")', new PermissionsPolicyListener(['encrypted_media' => ['self', 'https://cdn.example.com']])],
            ['interest-cohort=()', new PermissionsPolicyListener(['interest_cohort' => []])],
        ];
    }

    public function testSubRequest(): void
    {
        $listener = new PermissionsPolicyListener(['camera' => ['self']]);
        $response = $this->callListener($listener, '/', false);

        $this->assertNull($response->headers->get('Permissions-Policy'));
    }

    private function callListener(PermissionsPolicyListener $listener, string $path, bool $mainReq): Response
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
