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

use Nelmio\SecurityBundle\Encrypter;

class EncrypterTest extends \PHPUnit\Framework\TestCase
{
    public function setUp(): void
    {
        parent::setUp();

        if (!function_exists('mcrypt_module_open')) {
            $this->markTestSkipped('MCrypt is not installed');
        }
        if (PHP_VERSION_ID >= 70100 ) {
            $this->markTestSkipped('MCrypt is deprecated since PHP 7.1');
        }
    }

    /**
     * @expectedException InvalidArgumentException
     */
    public function testConstructorShouldVerifyAlgoritm()
    {
        new Encrypter('secret', 'invalid_algoritm');
    }

    /**
     * @group legacy
     * @expectedDeprecation Encrypted Cookie is now deprecated due to high coupling with the deprecated mcrypt extension, support will be removed in NelmioSecurityBundle version 3
     */
    public function testEncryption()
    {
        $encrypter = new Encrypter('secret', 'rijndael-128');

        $value = 'bar';
        $encryptedValue = $encrypter->encrypt($value);

        $this->assertNotEquals($encryptedValue, $value);

        $decrypted = $encrypter->decrypt($encryptedValue);

        $this->assertEquals($decrypted, $value);
    }
}
