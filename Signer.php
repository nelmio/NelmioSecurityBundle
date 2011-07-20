<?php

namespace Nelmio\SecurityBundle;

class Signer
{
    private $secret;
    private $algo;
    private $separator = '!$*-';

    public function __construct($secret, $algo = 'sha256')
    {
        $this->secret = $secret;
        $this->algo = $algo;

        if (!in_array($this->algo, hash_algos())) {
            throw new \InvalidArgumentException(sprintf("The supplied hashing algorithm '%s' is not supported by this system.",
                $this->algo));
        }
    }

    public function getSignedValue($value, $signature = null)
    {
        if (null === $signature) {
            $signature = $this->generateSignature($value);
        }
        return $value.$this->separator.$signature;
    }

    public function verifySignedValue($signedValue)
    {
        list($value, $signature) = $this->splitSignatureFromSignedValue($signedValue);

        return $signature === $this->generateSignature($value);
    }

    public function getVerifiedRawValue($signedValue)
    {
        if (!$this->verifySignedValue($signedValue)) {
            throw new \InvalidArgumentException(sprintf("The signature for '%s' was invalid.", $signedValue));
        }

        list($value, $signature) = $this->splitSignatureFromSignedValue($signedValue);
        return $value;
    }

    private function generateSignature($value)
    {
        return hash_hmac($this->algo, $value, $this->secret);
    }

    private function splitSignatureFromSignedValue($signedValue)
    {
        if (false === strpos($signedValue, $this->separator)) {
            return array($signedValue, null);
        }

        return explode($this->separator, $signedValue, 2);
    }
}
