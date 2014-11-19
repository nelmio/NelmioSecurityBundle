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

class EncrypterTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @expectedException InvalidArgumentException
     */
    public function testConstructorShouldVerifyAlgoritm()
    {
        new Encrypter('secret', 'invalid_algoritm');
    }

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
