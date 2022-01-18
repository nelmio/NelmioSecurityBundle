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

use Nelmio\SecurityBundle\Signer;
use Nelmio\SecurityBundle\EventListener\SignedCookieListener;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\ResponseHeaderBag;
use Symfony\Component\HttpKernel\HttpKernelInterface;

class SignedCookieListenerTest extends \PHPUnit\Framework\TestCase
{
    private $signer;
    private $kernel;

    protected function setUp()
    {
        $this->signer = new Signer('secret', 'sha1');
        $this->kernel = $this->getMockBuilder('Symfony\Component\HttpKernel\HttpKernelInterface')->getMock();
    }

    /**
     * @dataProvider provideCookieReading
     */
    public function testCookieReading($signedCookieNames, $inputCookies, $expectedCookies)
    {
        $listener = new SignedCookieListener($this->signer, $signedCookieNames);
        $request = Request::create('/', 'GET', array(), $inputCookies);

        if (class_exists('Symfony\Component\HttpKernel\Event\RequestEvent')) {
            $class = 'Symfony\Component\HttpKernel\Event\RequestEvent';
        } else {
            $class = 'Symfony\Component\HttpKernel\Event\GetResponseEvent';
        }

        $event = new $class($this->kernel, $request, HttpKernelInterface::MASTER_REQUEST);
        $listener->onKernelRequest($event);

        $this->assertSame($expectedCookies, $request->cookies->all());
    }

    public function provideCookieReading()
    {
        return array(
            array(array(), array(), array()),
            array(array(), array('foo' => 'bar'), array('foo' => 'bar')),
            array(array('foo'), array('foo' => 'bar'), array()),
            array(array('foo'), array('foo' => 'bar.ca3756f81d3728a023bdc8a622c0906f373b795e'), array('foo' => 'bar')),
            array(array('*'), array('foo' => 'bar.ca3756f81d3728a023bdc8a622c0906f373b795e'), array('foo' => 'bar')),
        );
    }

    /**
     * @dataProvider provideCookieWriting
     */
    public function testCookieWriting($signedCookieNames, $inputCookies, $expectedCookies)
    {
        $listener = new SignedCookieListener($this->signer, $signedCookieNames);
        $request = Request::create('/');

        $response = new Response();
        foreach ($inputCookies as $name => $cookie) {
            $response->headers->setCookie(method_exists('Symfony\\Component\\HttpFoundation\\Cookie', 'create') ? Cookie::create($name, $cookie) : new Cookie($name, $cookie));
        }

        if (class_exists('Symfony\Component\HttpKernel\Event\ResponseEvent')) {
            $class = 'Symfony\Component\HttpKernel\Event\ResponseEvent';
        } else {
            $class = 'Symfony\Component\HttpKernel\Event\FilterResponseEvent';
        }

        $event = new $class($this->kernel, $request, HttpKernelInterface::MASTER_REQUEST, $response);
        $listener->onKernelResponse($event);

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
            array(array('foo'), array('foo' => 'bar'), array('foo' => 'bar.ca3756f81d3728a023bdc8a622c0906f373b795e')),
            array(array('*'), array('foo' => 'bar'), array('foo' => 'bar.ca3756f81d3728a023bdc8a622c0906f373b795e')),
        );
    }

    public function testCookieReadingSkipsSubReqs()
    {
        $listener = new SignedCookieListener($this->signer, array('*'));
        $request = Request::create('/', 'GET', array(), array('foo' => 'bar'));

        if (class_exists('Symfony\Component\HttpKernel\Event\RequestEvent')) {
            $class = 'Symfony\Component\HttpKernel\Event\RequestEvent';
        } else {
            $class = 'Symfony\Component\HttpKernel\Event\GetResponseEvent';
        }

        $event = new $class($this->kernel, $request, HttpKernelInterface::SUB_REQUEST);
        $listener->onKernelRequest($event);

        $this->assertEquals('bar', $request->cookies->get('foo'));
    }

    public function testCookieWritingSkipsSubReqs()
    {
        $listener = new SignedCookieListener($this->signer, array('*'));
        $request = Request::create('/');

        $response = new Response();
        $response->headers->setCookie(method_exists('Symfony\\Component\\HttpFoundation\\Cookie', 'create') ? Cookie::create('foo', 'bar') : new Cookie('foo', 'bar'));

        if (class_exists('Symfony\Component\HttpKernel\Event\ResponseEvent')) {
            $class = 'Symfony\Component\HttpKernel\Event\ResponseEvent';
        } else {
            $class = 'Symfony\Component\HttpKernel\Event\FilterResponseEvent';
        }

        $event = new $class($this->kernel, $request, HttpKernelInterface::SUB_REQUEST, $response);
        $listener->onKernelResponse($event);

        $cookies = $response->headers->getCookies(ResponseHeaderBag::COOKIES_ARRAY);
        $this->assertEquals('bar', $cookies['']['/']['foo']->getValue());
    }
}
