<?php

/*
 * This file is part of the Nelmio SecurityBundle.
 *
 * (c) Nelmio <hello@nelm.io>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Nelmio\SecurityBundle;

class Signer
{
    private $secret;
    private $algo;

    public function __construct($secret, $algo)
    {
        $this->secret = $secret;
        $this->algo = $algo;

        if (!in_array($this->algo, hash_algos(), true)) {
            throw new \InvalidArgumentException(sprintf("The supplied hashing algorithm '%s' is not supported by this system.",
                $this->algo));
        }
    }

    public function getSignedValue($value, $signature = null)
    {
        if (null === $signature) {
            $signature = $this->generateSignature($value);
        }

        return $value.'.'.$signature;
    }

    public function verifySignedValue($signedValue)
    {
        list($value, $signature) = $this->splitSignatureFromSignedValue($signedValue);
        $signature2 = $this->generateSignature($value);

        if ($signature === null || strlen($signature) !== strlen($signature2)) {
            return false;
        }

        $result = 0;
        for ($i = 0, $j = strlen($signature); $i < $j; ++$i) {
            $result |= ord($signature[$i]) ^ ord($signature2[$i]);
        }

        return 0 === $result;
    }

    public function getVerifiedRawValue($signedValue)
    {
        if (!$this->verifySignedValue($signedValue)) {
            throw new \InvalidArgumentException(sprintf("The signature for '%s' was invalid.", $signedValue));
        }

        $valueSignatureTuple = $this->splitSignatureFromSignedValue($signedValue);

        return $valueSignatureTuple[0];
    }

    private function generateSignature($value)
    {
        return hash_hmac($this->algo, $value, $this->secret);
    }

    private function splitSignatureFromSignedValue($signedValue)
    {
        $pos = strrpos($signedValue, '.');
        if (false === $pos) {
            return array($signedValue, null);
        }

        return array(substr($signedValue, 0, $pos), substr($signedValue, $pos + 1));
    }
}
