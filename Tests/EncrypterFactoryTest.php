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

use Defuse\Crypto\Key;
use Nelmio\SecurityBundle\EncrypterFactory;

class EncrypterFactoryTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @dataProvider getMcryptParams
     */
    public function testMcryptCreation($adapter, $algorithm, $expectedClass)
    {
        if (!function_exists('mcrypt_module_open')) {
            $this->markTestSkipped('MCrypt is not installed');
        }
        $factory = new EncrypterFactory();
        $encrypter = $factory->getEncrypter($adapter, 'secret', $algorithm);
        $this->assertInstanceOf($expectedClass, $encrypter);
        $this->assertInstanceOf('\Nelmio\SecurityBundle\EncrypterInterface', $encrypter);
    }

    /**
     * @dataProvider getOpenSSLParams
     */
    public function testOpenSSLCreation($adapter, $expectedClass)
    {
        if (!extension_loaded('openssl')) {
            $this->markTestSkipped('OpenSSL is not installed');
        }
        $factory = new EncrypterFactory();
        /**
         * @var Key $key;
         */
        $key = Key::createNewRandomKey();
        $encrypter = $factory->getEncrypter($adapter, $key->saveToAsciiSafeString(), '');
        $this->assertInstanceOf($expectedClass, $encrypter);
        $this->assertInstanceOf('\Nelmio\SecurityBundle\EncrypterInterface', $encrypter);
    }

    public function getMcryptParams()
    {
        return array(
            array(
                'adapter' => 'mcrypt',
                'algorithm' => 'rijndael-256',
                'class' => '\Nelmio\SecurityBundle\Encrypter',
            ),
            array(
                'adapter' => 'default',
                'algorithm' => 'rijndael-256',
                'class' => '\Nelmio\SecurityBundle\Encrypter'
            ),
            array(
                'adapter' => '',
                'algorithm' => 'rijndael-256',
                'class' => '\Nelmio\SecurityBundle\Encrypter'
            ),
        );
    }

    public function getOpenSSLParams()
    {
        return array(
            array(
                'adapter' => 'openssl',
                'class' => '\Nelmio\SecurityBundle\OpenSSLEncrypter'
            ),
        );
    }
}
