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

use Nelmio\SecurityBundle\EventListener\ReferrerPolicyListener;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

class ReferrerPolicyListenerTest extends ListenerTestCase
{
    /**
     * @dataProvider provideVariousConfigs
     */
    public function testVariousConfig(string $expectedValue, ReferrerPolicyListener $listener): void
    {
        $response = $this->callListener($listener, '/', true);

        $this->assertSame($expectedValue, $response->headers->get('Referrer-Policy'));
    }

    public static function provideVariousConfigs(): array
    {
        return [
            ['', new ReferrerPolicyListener([])],
            ['no-referrer', new ReferrerPolicyListener(['no-referrer'])],
            ['no-referrer, strict-origin-when-cross-origin', new ReferrerPolicyListener(['no-referrer', 'strict-origin-when-cross-origin'])],
            ['no-referrer, no-referrer-when-downgrade, strict-origin-when-cross-origin', new ReferrerPolicyListener(['no-referrer', 'no-referrer-when-downgrade', 'strict-origin-when-cross-origin'])],
        ];
    }

    private function callListener(ReferrerPolicyListener $listener, string $path, bool $mainReq): Response
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
