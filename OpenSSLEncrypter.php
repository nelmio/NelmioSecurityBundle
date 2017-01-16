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

use Defuse\Crypto\Crypto;
use Defuse\Crypto\Key;

class OpenSSLEncrypter implements EncrypterInterface
{
    private $key;

    public function __construct($key)
    {
        $this->key = Key::loadFromAsciiSafeString($key);
    }

    public function encrypt($input)
    {
        if (empty($input)) {
            return;
        }

        return Crypto::encrypt($input, $this->key);
    }

    public function decrypt($cipherText)
    {
        if (empty($cipherText)) {
            return;
        }

        return Crypto::decrypt($cipherText, $this->key);
    }
}
