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

use Defuse\Crypto\Key;
use Nelmio\SecurityBundle\EventListener\EncryptedCookieListener;
use Nelmio\SecurityBundle\OpenSSLEncrypter;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Symfony\Component\HttpKernel\Event\FilterResponseEvent;
use Symfony\Component\HttpKernel\Event\GetResponseEvent;

class OpenSSLEncryptedCookieListenerTest extends \PHPUnit_Framework_TestCase
{
    private $encrypter;
    private $kernel;

    protected function setUp()
    {
        parent::setUp();

        if (!extension_loaded('openssl')) {
            $this->markTestSkipped('OpenSSL is not installed');
        }

        $this->encrypter = new OpenSSLEncrypter('def00000c844fea966017b9d57f169c20739866389c09daa5b9eb6adcf9cf432353cd303ed2a73ef66e1ed262b261eb23057135d5cf5719fc53989eeb690d7903fa4a576');
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
            array(array('foo'), array('foo' => 'def5020094970d7b82571c01b646a2cbcca4dce2a0a28b22adeaa172a04b7f6209e7121d2c35e3a826431540fcc7d9c3de15f27b9770c4fd68a4a4f101a61fe5c75db16ac9f70765fa1e7431cc3b5fc87c505490a193ee'), array('foo' => 'bar')),
            array(array('*'), array('foo' => 'def50200ecdd5771770a554147d73598ad5e7ba1ac0d113a5a8363a5dd575118bc1d61dca9c3a462a56c81eb040f9664208092491eba77a2965a6054969b0e425a2ec2fc4730954008b6fdbee717cf9dc38f99739defcb'), array('foo' => 'bar')),
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
            'foo' => 'bar',
            'symfony' => 'rocks',
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
