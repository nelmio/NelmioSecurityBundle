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

namespace Nelmio\SecurityBundle\ContentSecurityPolicy;

class NonceGenerator
{
    /**
     * @var int<1, max>
     */
    private int $numberOfBytes;

    /**
     * @param int<1, max> $numberOfBytes
     */
    public function __construct(int $numberOfBytes)
    {
        $this->numberOfBytes = $numberOfBytes;
    }

    /**
     * Generates a nonce value that is later used in script and style policies.
     */
    public function generate(): string
    {
        return base64_encode(random_bytes($this->numberOfBytes));
    }
}
