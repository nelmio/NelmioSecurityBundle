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
     * @expectedException InvalidArgumentException
     */
    public function testConstructorShouldVerifyAlgoritm()
    {
        new OpenSSLEncrypter('secret', 'invalid_algoritm');
    }

    public function testEncryption()
    {
        $encrypter = new OpenSSLEncrypter('secret', 'AES-256-CBC');

        $value = 'bar';
        $encryptedValue = $encrypter->encrypt($value);

        $this->assertNotEquals($encryptedValue, $value);

        $decrypted = $encrypter->decrypt($encryptedValue);

        $this->assertEquals($decrypted, $value);
    }
}
