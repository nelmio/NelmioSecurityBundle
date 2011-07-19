<?php

namespace Nelmio\SecurityBundle;

class Signer
{
    private $secret;
    private $separator = '!$*-';

    public function __construct($secret)
    {
        $this->secret = $secret;
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
        return hash_hmac('sha1', $value, $this->secret);
    }

    private function splitSignatureFromSignedValue($signedValue)
    {
        if (false === strpos($signedValue, $this->separator)) {
            return array($signedValue, null);
        }

        return explode($this->separator, $signedValue, 2);
    }
}
