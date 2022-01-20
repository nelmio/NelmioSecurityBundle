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

use Nelmio\SecurityBundle\EventListener\XssProtectionListener;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;

class XssProtectionListenerTest extends \PHPUnit\Framework\TestCase
{
    private $kernel;

    protected function setUp(): void
    {
        $this->kernel = $this->getMockBuilder(HttpKernelInterface::class)->getMock();
    }

    /**
     * @dataProvider provideVariousConfigs
     */
    public function testVariousConfig($expectedValue, $listener)
    {
        $response = $this->callListener($listener, '/', true);

        $this->assertEquals($expectedValue, $response->headers->get('X-Xss-Protection'));
    }

    public function provideVariousConfigs()
    {
        return [
            ['0', new XssProtectionListener(false, false)],
            ['1', new XssProtectionListener(true, false)],
            ['0', new XssProtectionListener(false, true)],
            ['1; mode=block', new XssProtectionListener(true, true)],
            ['1; mode=block; report=https://report.com/endpoint', new XssProtectionListener(true, true, 'https://report.com/endpoint')],
        ];
    }

    protected function callListener(XssProtectionListener $listener, $path, $masterReq)
    {
        $request = Request::create($path);
        $response = new Response();

        if (class_exists(ResponseEvent::class)) {
            $class = ResponseEvent::class;
        } else {
            $class = 'Symfony\Component\HttpKernel\Event\FilterResponseEvent';
        }

        $event = new $class(
            $this->kernel,
            $request,
            $masterReq ? HttpKernelInterface::MASTER_REQUEST : HttpKernelInterface::SUB_REQUEST,
            $response
        );
        $listener->onKernelResponse($event);

        return $response;
    }
}
