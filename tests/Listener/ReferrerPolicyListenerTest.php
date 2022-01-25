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
use PHPUnit\Framework\MockObject\Stub;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;

class ReferrerPolicyListenerTest extends TestCase
{
    /**
     * @var Stub&HttpKernelInterface
     */
    private $kernel;

    protected function setUp(): void
    {
        $this->kernel = $this->createStub(HttpKernelInterface::class);
    }

    /**
     * @dataProvider provideVariousConfigs
     */
    public function testVariousConfig(string $expectedValue, ReferrerPolicyListener $listener): void
    {
        $response = $this->callListener($listener, '/', true);

        $this->assertSame($expectedValue, $response->headers->get('Referrer-Policy'));
    }

    public function provideVariousConfigs(): array
    {
        return [
            ['', new ReferrerPolicyListener([])],
            ['no-referrer', new ReferrerPolicyListener(['no-referrer'])],
            ['no-referrer, strict-origin-when-cross-origin', new ReferrerPolicyListener(['no-referrer', 'strict-origin-when-cross-origin'])],
            ['no-referrer, no-referrer-when-downgrade, strict-origin-when-cross-origin', new ReferrerPolicyListener(['no-referrer', 'no-referrer-when-downgrade', 'strict-origin-when-cross-origin'])],
        ];
    }

    protected function callListener(ReferrerPolicyListener $listener, string $path, bool $masterReq): Response
    {
        $request = Request::create($path);
        $response = new Response();

        $event = new ResponseEvent(
            $this->kernel,
            $request,
            $masterReq ? HttpKernelInterface::MASTER_REQUEST : HttpKernelInterface::SUB_REQUEST,
            $response
        );
        $listener->onKernelResponse($event);

        return $response;
    }
}
