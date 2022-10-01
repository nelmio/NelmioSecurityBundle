<?php

declare(strict_types=1);

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
use PHPUnit\Framework\TestCase;

class SignerTest extends TestCase
{
    public function testConstructorShouldVerifyHashAlgo(): void
    {
        $this->expectException('InvalidArgumentException');

        new Signer('secret', 'invalid_hash_algo');
    }

    public function testShouldVerifyValidSignature(): void
    {
        $signer = new Signer('secret', 'sha1');

        $value = 'foobar';
        $signedValue = $signer->getSignedValue($value);
        $this->assertNotSame($signedValue, $value);

        $this->assertFalse($signer->verifySignedValue($value));
        $this->assertTrue($signer->verifySignedValue($signedValue));
    }

    public function testShouldRejectInvalidSignature(): void
    {
        $signer = new Signer('secret', 'sha1');

        $value = 'foobar';
        $signedValue = $signer->getSignedValue($value, 'fake signature');

        $this->assertFalse($signer->verifySignedValue($signedValue));
    }

    public function testThrowsExceptionWithInvalidSignature(): void
    {
        $signer = new Signer('secret', 'sha1');

        $this->expectException(\InvalidArgumentException::class);

        $signer->getVerifiedRawValue('invalid_signed_value');
    }

    public function testSignatureShouldDependOnSecret(): void
    {
        $signer1 = new Signer('secret1', 'sha1');
        $signer2 = new Signer('secret2', 'sha1');

        $this->assertNotSame($signer1->getSignedValue('foobar'), $signer2->getSignedValue('foobar'));
    }
}
