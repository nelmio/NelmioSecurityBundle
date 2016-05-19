<?php
/**
 * @author @jayS-de <jens.schulze@commercetools.de>
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
                return new OpenSSLEncrypter($secret, $algorithm);
            default:
                return new Encrypter($secret, $algorithm);
        }
    }
}
