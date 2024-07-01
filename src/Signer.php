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
            throw new \InvalidArgumentException(sprintf("The supplied hashing algorithm '%s' is not supported by this system.", $this->algo));
        }

        if (null !== $this->legacyAlgo && !\in_array($this->legacyAlgo, hash_algos(), true)) {
            throw new \InvalidArgumentException(sprintf("The supplied legacy hashing algorithm '%s' is not supported by this system.", $this->legacyAlgo));
        }
    }

    public function getSignedValue(string $value, ?string $signature = null): string
    {
        if (null === $signature) {
            $signature = $this->generateSignature($value, $this->algo);
        }

        return implode($this->separator, [$value, $signature, $this->algo]);
    }

    public function verifySignedValue(string $signedValue): bool
    {
        [$value, $signature, $algorithm] = $this->splitSignedValue($signedValue);
        if (null === $algorithm || !\in_array($algorithm, $this->allowedAlgorithms(), true)) {
            return false;
        }

        $signature2 = $this->generateSignature($value, $algorithm);
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

        $valueSignatureTuple = $this->splitSignedValue($signedValue);

        return $valueSignatureTuple[0];
    }

    private function generateSignature(string $value, string $algo): string
    {
        return hash_hmac($algo, $value, $this->secret);
    }

    /**
     * @return array{string, string|null, string|null}
     */
    private function splitSignedValue(string $signedValue): array
    {
        $parts = explode($this->separator, $signedValue);
        $length = \count($parts);
        if ($length >= 3) {
            return [
                implode($this->separator, \array_slice($parts, 0, $length - 2)),
                $parts[$length - 2],
                $parts[$length - 1],
            ];
        }

        if (2 === \count($parts)) {
            return [$parts[0], $parts[1], $this->legacyAlgo ?? $this->algo];
        }

        return [implode($this->separator, $parts), null, null];
    }

    /**
     * @return string[]
     */
    private function allowedAlgorithms(): array
    {
        if (null === $this->legacyAlgo) {
            return [$this->algo];
        }

        return [$this->algo, $this->legacyAlgo];
    }
}
