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

namespace Nelmio\SecurityBundle\ExternalRedirect;

class WhitelistBasedTargetValidator implements TargetValidator
{
    /**
     * @var string|null
     */
    private $whitelist;

    /**
     * @param string[]|string|null $whitelist
     */
    public function __construct($whitelist = null)
    {
        if (\is_array($whitelist)) {
            if ([] !== $whitelist) {
                $whitelist = array_map(static function (string $el): string {
                    return preg_quote(ltrim($el, '.'));
                }, $whitelist);
                $whitelist = '(?:.*\.'.implode('|.*\.', $whitelist).'|'.implode('|', $whitelist).')';
            } else {
                $whitelist = null;
            }
        }
        $this->whitelist = $whitelist;
    }

    public function isTargetAllowed(string $targetUrl): bool
    {
        if (null === $this->whitelist || '' === $this->whitelist) {
            return false;
        }

        $host = parse_url($targetUrl, \PHP_URL_HOST);

        if (!\is_string($host)) {
            throw new \InvalidArgumentException(sprintf('Url "%s" does not contain a host name.', $targetUrl));
        }

        return preg_match('{^'.$this->whitelist.'$}i', $host) > 0;
    }
}
