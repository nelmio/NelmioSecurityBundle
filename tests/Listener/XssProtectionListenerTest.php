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
use PHPUnit\Framework\MockObject\Stub;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;

class XssProtectionListenerTest extends TestCase
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
    public function testVariousConfig(string $expectedValue, XssProtectionListener $listener): void
    {
        $response = $this->callListener($listener, '/', true);

        $this->assertEquals($expectedValue, $response->headers->get('X-Xss-Protection'));
    }

    public function provideVariousConfigs(): array
    {
        return [
            ['0', new XssProtectionListener(false, false)],
            ['1', new XssProtectionListener(true, false)],
            ['0', new XssProtectionListener(false, true)],
            ['1; mode=block', new XssProtectionListener(true, true)],
            ['1; mode=block; report=https://report.com/endpoint', new XssProtectionListener(true, true, 'https://report.com/endpoint')],
        ];
    }

    protected function callListener(XssProtectionListener $listener, string $path, bool $masterReq): Response
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
