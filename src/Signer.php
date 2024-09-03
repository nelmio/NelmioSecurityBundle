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

use Nelmio\SecurityBundle\Signer\SignerInterface;

final class Signer implements SignerInterface
{
    private string $secret;
    private string $algo;
    private ?string $legacyAlgo;

    /**
     * @var non-empty-string
     */
    private string $separator;

    /**
     * @param non-empty-string $separator
     */
    public function __construct(string $secret, string $algo, ?string $legacyAlgo = null, string $separator = '.')
    {
        $this->secret = $secret;
        $this->algo = $algo;
        $this->legacyAlgo = $legacyAlgo;
        $this->separator = $separator;

        if (!\in_array($this->algo, hash_algos(), true)) {
            throw new \InvalidArgumentException(\sprintf("The supplied hashing algorithm '%s' is not supported by this system.", $this->algo));
        }

        if (null !== $this->legacyAlgo && !\in_array($this->legacyAlgo, hash_algos(), true)) {
            throw new \InvalidArgumentException(\sprintf("The supplied legacy hashing algorithm '%s' is not supported by this system.", $this->legacyAlgo));
        }
    }

    public function getSignedValue(string $value, ?string $signature = null): string
    {
        if (null === $signature) {
            $signature = $this->generateSignature($value, $this->algo);
        }

        return $value.$this->separator.$signature;
    }

    public function verifySignedValue(string $signedValue): bool
    {
        [$value, $signature] = $this->splitSignatureFromSignedValue($signedValue);
        if (null === $signature) {
            return false;
        }

        $expectedSignature = $this->generateSignature($value, $this->algo);
        if (hash_equals($expectedSignature, $signature)) {
            return true;
        }

        if (null === $this->legacyAlgo) {
            return false;
        }

        $expectedLegacySignature = $this->generateSignature($value, $this->legacyAlgo);

        return hash_equals($expectedLegacySignature, $signature);
    }

    public function getVerifiedRawValue(string $signedValue): string
    {
        if (!$this->verifySignedValue($signedValue)) {
            throw new \InvalidArgumentException(\sprintf("The signature for '%s' was invalid.", $signedValue));
        }

        $valueSignatureTuple = $this->splitSignatureFromSignedValue($signedValue);

        return $valueSignatureTuple[0];
    }

    private function generateSignature(string $value, string $algo): string
    {
        return hash_hmac($algo, $value, $this->secret);
    }

    /**
     * @return array{string, string|null}
     */
    private function splitSignatureFromSignedValue(string $signedValue): array
    {
        $pos = strrpos($signedValue, $this->separator);
        if (false === $pos) {
            return [$signedValue, null];
        }

        return [substr($signedValue, 0, $pos), substr($signedValue, $pos + 1)];
    }
}
