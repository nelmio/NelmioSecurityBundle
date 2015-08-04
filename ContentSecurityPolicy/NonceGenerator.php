<?php
namespace Nelmio\SecurityBundle\ContentSecurityPolicy;

use Symfony\Component\Security\Core\Util\SecureRandom;

class NonceGenerator
{
    const NONCE_PREFIX = 'nonce-';

    /**
     * @var integer
     */
    private $numberOfBytes;

    /**
     * @var string
     */
    private $currentNonce;

    /**
     * @var SecureRandom
     */
    private $secureRandom;

    public function __construct(SecureRandom $secureRandom, $numberOfBytes)
    {
        $this->numberOfBytes = $numberOfBytes;
        $this->secureRandom = $secureRandom;
    }

    /**
     * Generates a nonce value that is later used in script and style policies
     *
     * @return string
     */
    public function generate()
    {
        $this->currentNonce = $this->buildNonce();
        return $this->currentNonce;
    }

    /**
     * Returns the previously generated nonce on null if no nonce was previously generated
     *
     * @return string|null
     */
    public function getCurrentNonce()
    {
        return $this->currentNonce;
    }

    /**
     * Returns the previously generated nonce with a nonce prefix and quotes that value
     *
     * @return string|null
     */
    public function getCurrentNonceForHeaders()
    {
        if ($this->currentNonce === null) {
            return null;
        }

        return $this->prepareNonceForHeaders($this->currentNonce);
    }

    /**
     * @return string
     */
    protected function buildNonce()
    {
        $randomBytes = $this->secureRandom->nextBytes($this->numberOfBytes);
        return bin2hex($randomBytes);
    }

    /**
     * @param string $nonce
     * @return string
     */
    protected function prepareNonceForHeaders($nonce)
    {
        return sprintf("'%s%s'", self::NONCE_PREFIX, $nonce);
    }
}
