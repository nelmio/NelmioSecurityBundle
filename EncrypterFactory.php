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

class EncrypterFactory
{
    /**
     * @param string $adapter
     * @param string $secret
     * @param string $algorithm
     * @return EncrypterInterface
     */
    public function getEncrypter($adapter, $secret, $algorithm)
    {
        switch ($adapter) {
            case 'openssl':
                return new OpenSSLEncrypter($secret);
            default:
                return new Encrypter($secret, $algorithm);
        }
    }
}
