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

namespace Nelmio\SecurityBundle\Signer;

interface SignerInterface
{
    public function getSignedValue(string $value, ?string $signature = null): string;

    public function verifySignedValue(string $signedValue): bool;

    public function getVerifiedRawValue(string $signedValue): string;
}
