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

    public function testConstructorShouldVerifyHashLegacyAlgo(): void
    {
        $this->expectException('InvalidArgumentException');

        new Signer('secret', hash_algos()[0], 'invalid_hash_algo');
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

    public function testShouldRejectMissingSignature(): void
    {
        $signer = new Signer('secret', 'sha1');

        $this->assertFalse($signer->verifySignedValue('foobar'));
        $this->assertFalse($signer->verifySignedValue('foobar.'));
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

    public function testHandlesValueWithSeparator(): void
    {
        $value = 'foo.bar';

        $signer = new Signer('secret1', 'sha3-256', null, '.');
        $signature = $signer->getSignedValue($value);

        $this->assertTrue($signer->verifySignedValue($signature));
        $this->assertSame($value, $signer->getVerifiedRawValue($signature));
    }

    public function testHandlesCustomSeparator(): void
    {
        $value = 'foobar';

        $signer = new Signer('secret1', 'sha3-256', null, ';');
        $signature = $signer->getSignedValue($value);

        $this->assertTrue($signer->verifySignedValue($signature));
        $this->assertSame($value, $signer->getVerifiedRawValue($signature));
        $this->assertStringContainsString(';', $signature);
    }

    public function testShouldVerifyValidLegacySignature(): void
    {
        $value = 'foobar.7f5c0e9cb2f07137b1c0249108d5c400a3c39be5';

        $signer = new Signer('secret', 'sha3-256', 'sha1');

        $this->assertTrue($signer->verifySignedValue($value));
    }

    public function testShouldRejectInvalidLegacySignature(): void
    {
        $signer = new Signer('secret', 'sha3-256', 'sha256');

        $this->assertFalse($signer->verifySignedValue('foobar.not_a_signature'));
        $this->assertFalse($signer->verifySignedValue('foobar.7f5c0e9cb2f07137b1c0249108d5c400a3c39be5'));
    }
}
