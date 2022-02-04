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

namespace Nelmio\SecurityBundle;

final class Signer
{
    private string $secret;
    private string $algo;

    public function __construct(string $secret, string $algo)
    {
        $this->secret = $secret;
        $this->algo = $algo;

        if (!\in_array($this->algo, hash_algos(), true)) {
            throw new \InvalidArgumentException(sprintf("The supplied hashing algorithm '%s' is not supported by this system.", $this->algo));
        }
    }

    public function getSignedValue(string $value, ?string $signature = null): string
    {
        if (null === $signature) {
            $signature = $this->generateSignature($value);
        }

        return $value.'.'.$signature;
    }

    public function verifySignedValue(string $signedValue): bool
    {
        [$value, $signature] = $this->splitSignatureFromSignedValue($signedValue);
        $signature2 = $this->generateSignature($value);

        if (null === $signature || \strlen($signature) !== \strlen($signature2)) {
            return false;
        }

        $result = 0;
        for ($i = 0, $j = \strlen($signature); $i < $j; ++$i) {
            $result |= \ord($signature[$i]) ^ \ord($signature2[$i]);
        }

        return 0 === $result;
    }

    public function getVerifiedRawValue(string $signedValue): string
    {
        if (!$this->verifySignedValue($signedValue)) {
            throw new \InvalidArgumentException(sprintf("The signature for '%s' was invalid.", $signedValue));
        }

        $valueSignatureTuple = $this->splitSignatureFromSignedValue($signedValue);

        return $valueSignatureTuple[0];
    }

    private function generateSignature(string $value): string
    {
        return hash_hmac($this->algo, $value, $this->secret);
    }

    /**
     * @return array{string, string|null}
     */
    private function splitSignatureFromSignedValue(string $signedValue): array
    {
        $pos = strrpos($signedValue, '.');
        if (false === $pos) {
            return [$signedValue, null];
        }

        return [substr($signedValue, 0, $pos), substr($signedValue, $pos + 1)];
    }
}
