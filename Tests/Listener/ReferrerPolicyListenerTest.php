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

use Nelmio\SecurityBundle\EventListener\ReferrerPolicyListener;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\FilterResponseEvent;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;

class ReferrerPolicyListenerTest extends \PHPUnit\Framework\TestCase
{
    private $kernel;

    protected function setUp()
    {
        $this->kernel = $this->getMockBuilder('Symfony\Component\HttpKernel\HttpKernelInterface')->getMock();
    }

    /**
     * @dataProvider provideVariousConfigs
     */
    public function testVariousConfig($expectedValue, $listener)
    {
        $response = $this->callListener($listener, '/', true);

        $this->assertEquals($expectedValue, $response->headers->get('Referrer-Policy'));
    }

    public function provideVariousConfigs()
    {
        return array(
            array('', new ReferrerPolicyListener(array())),
            array('no-referrer', new ReferrerPolicyListener(array('no-referrer'))),
            array('no-referrer, strict-origin-when-cross-origin', new ReferrerPolicyListener(array('no-referrer', 'strict-origin-when-cross-origin'))),
            array('no-referrer, no-referrer-when-downgrade, strict-origin-when-cross-origin', new ReferrerPolicyListener(array('no-referrer', 'no-referrer-when-downgrade', 'strict-origin-when-cross-origin'))),
        );
    }

    protected function callListener(ReferrerPolicyListener $listener, $path, $masterReq)
    {
        $request = Request::create($path);
        $response = new Response();

        if (class_exists(ResponseEvent::class)) {
            $class = ResponseEvent::class;
        } else {
            $class = FilterResponseEvent::class;
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
