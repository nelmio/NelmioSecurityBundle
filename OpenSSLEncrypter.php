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

class OpenSSLEncrypter implements EncrypterInterface
{
    private $secret;
    private $algorithm;
    private $ivSize;

    public function __construct($secret, $algorithm)
    {
        $this->secret = substr($secret, 0, 32);
        $this->algorithm = $algorithm;

        if (!extension_loaded('openssl')) {
            throw new \RuntimeException('You need to install openssl if you want to encrypt your cookies.');
        }
        $methods = openssl_get_cipher_methods(true);
        if (in_array($this->algorithm, $methods) === false) {
            throw new \InvalidArgumentException(sprintf("The supplied encryption algorithm '%s' is not supported by this system.",
                $this->algorithm));
        }

        $this->ivSize = openssl_cipher_iv_length($this->algorithm);
    }

    public function encrypt($input)
    {
        if (empty($input)) {
            return;
        }

        $iv = random_bytes($this->ivSize);
        return rtrim(base64_encode($iv . openssl_encrypt((string)$input, $this->algorithm, $this->secret, false, $iv)), '=');

    }

    public function decrypt($input)
    {
        if (empty($input)) {
            return;
        }

        $encryptedData = base64_decode($input, true);

        $iv = substr($encryptedData, 0, $this->ivSize);

        if (strlen($iv) < $this->ivSize) {
            return;
        }

        $encryptedData = substr($encryptedData, $this->ivSize);

        return rtrim(openssl_decrypt($encryptedData, $this->algorithm, $this->secret, false, $iv), '\0');
    }
}
