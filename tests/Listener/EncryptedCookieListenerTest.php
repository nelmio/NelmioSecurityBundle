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

class EncryptedCookieListenerTest extends \PHPUnit\Framework\TestCase
{
    private $encrypter;
    private $kernel;

    protected function setUp()
    {
        parent::setUp();

        if (!function_exists('mcrypt_module_open')) {
            $this->markTestSkipped('MCrypt is not installed');
        }

        if (PHP_VERSION_ID >= 70100 ) {
            $this->markTestSkipped('MCrypt is deprecated since PHP 7.1');
        }

        $this->encrypter = new Encrypter('secret', 'rijndael-128');
        $this->kernel = $this->getMockBuilder('Symfony\Component\HttpKernel\HttpKernelInterface')->getMock();
    }

    /**
     * @dataProvider provideCookieReading
     * @group legacy
     * @expectedDeprecation Encrypted Cookie is now deprecated due to high coupling with the deprecated mcrypt extension, support will be removed in NelmioSecurityBundle version 3
     */
    public function testCookieReading($encryptedCookieNames, $inputCookies, $expectedCookies)
    {
        $listener = new EncryptedCookieListener($this->encrypter, $encryptedCookieNames);
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
            array(array('foo'), array('foo' => 'BX9knwx1sPhIGxTxukVfsA0o0m/KRm4kMwwEYn/etMw'), array('foo' => 'bar')),
            array(array('*'), array('foo' => 'yNrfCriKHLxUtuZUInRlNsOjbLcL5a/4M8oDDXzt2aI'), array('foo' => 'bar')),
        );
    }

    /**
     * @dataProvider provideCookieWritingWithoutEncryption
     * @group legacy
     * @expectedDeprecation Encrypted Cookie is now deprecated due to high coupling with the deprecated mcrypt extension, support will be removed in NelmioSecurityBundle version 3
     */
    public function testCookieWritingWithoutEncryption($encryptedCookieNames, $inputCookies, $expectedCookies)
    {
        $listener = new EncryptedCookieListener($this->encrypter, $encryptedCookieNames);
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

    public function provideCookieWritingWithoutEncryption()
    {
        return array(
            array(array(), array(), array()),
            array(array(), array('foo' => 'bar'), array('foo' => 'bar')),
        );
    }

    /**
     * @group legacy
     * @expectedDeprecation Encrypted Cookie is now deprecated due to high coupling with the deprecated mcrypt extension, support will be removed in NelmioSecurityBundle version 3
     */
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

        $this->assertNotSame($inputCookies, $responseCookieValues);

        $request = Request::create('/', 'GET', array(), $responseCookieValues);

        if (class_exists('Symfony\Component\HttpKernel\Event\RequestEvent')) {
            $class = 'Symfony\Component\HttpKernel\Event\RequestEvent';
        } else {
            $class = 'Symfony\Component\HttpKernel\Event\GetResponseEvent';
        }

        $event = new $class($this->kernel, $request, HttpKernelInterface::MASTER_REQUEST);
        $listener->onKernelRequest($event);

        $this->assertSame($inputCookies, $request->cookies->all());
    }
}
