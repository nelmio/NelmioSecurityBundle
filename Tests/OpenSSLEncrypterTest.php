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
use Nelmio\SecurityBundle\OpenSSLEncrypter;

class OpenSSLEncrypterTest extends \PHPUnit_Framework_TestCase
{
    public function setUp()
    {
        parent::setUp();

        if (!extension_loaded('openssl')) {
            $this->markTestSkipped('OpenSSL is not installed');
        }
    }

    /**
     * @expectedException \Defuse\Crypto\Exception\BadFormatException
     */
    public function testConstructorShouldVerifyKey()
    {
        new OpenSSLEncrypter('secret');
    }

    public function testEncryption()
    {
        /**
         * @var Key $key
         */
        $key = Key::createNewRandomKey();
        $encrypter = new OpenSSLEncrypter($key->saveToAsciiSafeString());

        $value = 'bar';
        $encryptedValue = $encrypter->encrypt($value);

        $this->assertNotEquals($encryptedValue, $value);

        $decrypted = $encrypter->decrypt($encryptedValue);

        $this->assertEquals($decrypted, $value);
    }
}
