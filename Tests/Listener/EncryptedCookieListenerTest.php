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

use Nelmio\SecurityBundle\Encrypter;
use Nelmio\SecurityBundle\EventListener\EncryptedCookieListener;

use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Symfony\Component\HttpKernel\Event\FilterResponseEvent;
use Symfony\Component\HttpKernel\Event\GetResponseEvent;

class EncryptedCookieListenerTest extends \PHPUnit_Framework_TestCase
{
    private $encrypter;
    private $kernel;

    protected function setUp()
    {
        $this->encrypter = new Encrypter('secret', 'rijndael-128');
        $this->kernel = $this->getMock('Symfony\Component\HttpKernel\HttpKernelInterface');
    }

    /**
     * @dataProvider provideCookieReading
     */
    public function testCookieReading($encryptedCookieNames, $inputCookies, $expectedCookies)
    {
        $listener = new EncryptedCookieListener($this->encrypter, $encryptedCookieNames);
        $request = Request::create('/', 'GET', array(), $inputCookies);

        $event = new GetResponseEvent($this->kernel, $request, HttpKernelInterface::MASTER_REQUEST);
        $listener->onKernelRequest($event);

        $this->assertSame($expectedCookies, $request->cookies->all());
    }

    public function provideCookieReading()
    {
        return array(
            array(array(), array(), array()),
            array(array(), array('foo' => 'bar'), array('foo' => 'bar')),
            array(array('foo'), array('foo' => 'BX9knwx1sPhIGxTxukVfsA0o0m/KRm4kMwwEYn/etMw'), array('foo' => 'bar')),
            array(array('*'), array('foo' => 'yNrfCriKHLxUtuZUInRlNsOjbLcL5a/4M8oDDXzt2aI'), array('foo' => 'bar')),
        );
    }

    /**
     * @dataProvider provideCookieWritingWithoutEncryption
     */
    public function testCookieWritingWithoutEncryption($encryptedCookieNames, $inputCookies, $expectedCookies)
    {
        $listener = new EncryptedCookieListener($this->encrypter, $encryptedCookieNames);
        $request = Request::create('/');

        $response = new Response();
        foreach ($inputCookies as $name => $cookie) {
            $response->headers->setCookie(new Cookie($name, $cookie));
        }

        $event = new FilterResponseEvent($this->kernel, $request, HttpKernelInterface::MASTER_REQUEST, $response);
        $listener->onKernelResponse($event);

        $responseCookieValues = array();
        foreach ($response->headers->getCookies() as $cookie) {
            $responseCookieValues[$cookie->getName()] = $cookie->getValue();
        }

        $this->assertSame($expectedCookies, $responseCookieValues);
    }

    public function provideCookieWritingWithoutEncryption()
    {
        return array(
            array(array(), array(), array()),
            array(array(), array('foo' => 'bar'), array('foo' => 'bar')),
        );
    }

    public function testCookieWritingWithEncryption()
    {
        $inputCookies = array(
            'foo'       => 'bar',
            'symfony'   => 'rocks'
        );

        $listener = new EncryptedCookieListener($this->encrypter, array('*'));
        $request = Request::create('/');

        $response = new Response();
        foreach ($inputCookies as $name => $cookie) {
            $response->headers->setCookie(new Cookie($name, $cookie));
        }

        $event = new FilterResponseEvent($this->kernel, $request, HttpKernelInterface::MASTER_REQUEST, $response);
        $listener->onKernelResponse($event);

        $responseCookieValues = array();
        foreach ($response->headers->getCookies() as $cookie) {
            $responseCookieValues[$cookie->getName()] = $cookie->getValue();
        }

        $this->assertNotSame($inputCookies, $responseCookieValues);

        $request = Request::create('/', 'GET', array(), $responseCookieValues);

        $event = new GetResponseEvent($this->kernel, $request, HttpKernelInterface::MASTER_REQUEST);
        $listener->onKernelRequest($event);

        $this->assertSame($inputCookies, $request->cookies->all());
    }
}
