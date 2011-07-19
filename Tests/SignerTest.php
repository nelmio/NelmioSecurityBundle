<?php

namespace Nelmio\SecurityBundle\Tests;

use Nelmio\SecurityBundle\Signer;

class SignerTest extends \PHPUnit_Framework_TestCase
{
    public function testShouldVerifyValidSignature()
    {
        $signer = new Signer('secret');

        $value = 'foobar';
        $signedValue = $signer->getSignedValue($value);
        $this->assertNotSame($signedValue, $value);

        $this->assertFalse($signer->verifySignedValue($value));
        $this->assertTrue($signer->verifySignedValue($signedValue));
    }

    public function testShouldRejectInvalidSignature()
    {
        $signer = new Signer('secret');

        $value = 'foobar';
        $signedValue = $signer->getSignedValue($value, 'fake signature');

        $this->assertFalse($signer->verifySignedValue($signedValue));
    }

    public function testSignatureShouldDependOnSecret()
    {
        $signer1 = new Signer('secret1');
        $signer2 = new Signer('secret2');

        $this->assertNotSame($signer1->getSignedValue('foobar'), $signer2->getSignedValue('foobar'));
    }
}
