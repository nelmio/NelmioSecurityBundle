<?php

/*
 * This file is part of the Nelmio SecurityBundle.
 *
 * (c) Nelmio <hello@nelm.io>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Nelmio\SecurityBundle\Tests;

use Nelmio\SecurityBundle\Signer;
use Nelmio\SecurityBundle\SignedCookieListener;

use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Symfony\Component\HttpKernel\Event\FilterResponseEvent;
use Symfony\Component\HttpKernel\Event\GetResponseEvent;
use Symfony\Component\HttpKernel\KernelEvents;
use Symfony\Component\EventDispatcher\EventDispatcher;

class SignedCookieListenerTest extends \PHPUnit_Framework_TestCase
{
    private $dispatcher;
    private $signer;
    private $kernel;

    protected function setUp()
    {
        $this->dispatcher = new EventDispatcher();

        $this->signer = new Signer('secret', 'sha1');

        $this->kernel = $this->getMock('Symfony\Component\HttpKernel\HttpKernelInterface');
    }

    /**
     * @dataProvider provideCookieReading
     */
    public function testCookieReading($signedCookieNames, $inputCookies, $expectedCookies)
    {
        $listener = new SignedCookieListener($this->signer, $signedCookieNames);
        $this->dispatcher->addListener(KernelEvents::REQUEST, array($listener, 'onKernelRequest'));

        $request = Request::create('/', 'GET', array(), $inputCookies);

        $event = new GetResponseEvent($this->kernel, $request, HttpKernelInterface::MASTER_REQUEST);
        $this->dispatcher->dispatch(KernelEvents::REQUEST, $event);

        $this->assertSame($expectedCookies, $request->cookies->all());
    }


    public function provideCookieReading()
    {
        return array(
            array(array(), array(), array()),
            array(array(), array('foo' => 'bar'), array('foo' => 'bar')),
            array(array('foo'), array('foo' => 'bar'), array()),
            array(array('foo'), array('foo' => 'bar!$*-ca3756f81d3728a023bdc8a622c0906f373b795e'), array('foo' => 'bar')),
            array(array('*'), array('foo' => 'bar!$*-ca3756f81d3728a023bdc8a622c0906f373b795e'), array('foo' => 'bar')),
        );
    }

    /**
     * @dataProvider provideCookieWriting
     */
    public function testCookieWriting($signedCookieNames, $inputCookies, $expectedCookies)
    {
        $listener = new SignedCookieListener($this->signer, $signedCookieNames);
        $this->dispatcher->addListener(KernelEvents::RESPONSE, array($listener, 'onKernelResponse'));

        $request = Request::create('/');

        $response = new Response();
        foreach ($inputCookies as $name => $cookie) {
            $response->headers->setCookie(new Cookie($name, $cookie));
        }

        $event = new FilterResponseEvent($this->kernel, $request, HttpKernelInterface::MASTER_REQUEST, $response);
        $this->dispatcher->dispatch(KernelEvents::RESPONSE, $event);

        $responseCookieValues = array();
        foreach ($response->headers->getCookies() as $cookie) {
            $responseCookieValues[$cookie->getName()] = $cookie->getValue();
        }

        $this->assertSame($expectedCookies, $responseCookieValues);
    }

    public function provideCookieWriting()
    {
        return array(
            array(array(), array(), array()),
            array(array(), array('foo' => 'bar'), array('foo' => 'bar')),
            array(array('foo'), array('foo' => 'bar'), array('foo' => 'bar!$*-ca3756f81d3728a023bdc8a622c0906f373b795e')),
            array(array('*'), array('foo' => 'bar'), array('foo' => 'bar!$*-ca3756f81d3728a023bdc8a622c0906f373b795e')),
        );
    }
}
