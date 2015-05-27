<?php

namespace Nelmio\SecurityBundle\Tests\Listener;

use Nelmio\SecurityBundle\EventListener\XssProtectionListener;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\FilterResponseEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;

class XssProtectionListenerTest extends \PHPUnit_Framework_TestCase
{
    private $kernel;

    protected function setUp()
    {
        $this->kernel = $this->getMock('Symfony\Component\HttpKernel\HttpKernelInterface');
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
        return array(
            array('0', new XssProtectionListener(false, false)),
            array('1', new XssProtectionListener(true, false)),
            array('0', new XssProtectionListener(false, true)),
            array('1; mode=block', new XssProtectionListener(true, true)),
        );
    }

    protected function callListener(XssProtectionListener $listener, $path, $masterReq)
    {
        $request  = Request::create($path);
        $response = new Response();

        $event = new FilterResponseEvent(
            $this->kernel,
            $request,
            $masterReq ? HttpKernelInterface::MASTER_REQUEST : HttpKernelInterface::SUB_REQUEST,
            $response
        );
        $listener->onKernelResponse($event);

        return $response;
    }
}
