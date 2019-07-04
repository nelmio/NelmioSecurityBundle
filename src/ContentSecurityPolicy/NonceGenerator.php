<?php

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
     * @var int
     */
    private $numberOfBytes;

    public function __construct($numberOfBytes)
    {
        $this->numberOfBytes = $numberOfBytes;
    }

    /**
     * Generates a nonce value that is later used in script and style policies.
     *
     * @return string
     */
    public function generate()
    {
        return base64_encode(random_bytes($this->numberOfBytes));
    }
}
