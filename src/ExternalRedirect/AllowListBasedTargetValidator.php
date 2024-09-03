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

final class AllowListBasedTargetValidator implements TargetValidator
{
    private ?string $allowList;

    /**
     * @param string[]|string|null $allowList
     */
    public function __construct($allowList = null)
    {
        if (\is_array($allowList)) {
            if ([] !== $allowList) {
                $allowList = array_map(static function (string $el): string {
                    return preg_quote(ltrim($el, '.'));
                }, $allowList);
                $allowList = '(?:.*\.'.implode('|.*\.', $allowList).'|'.implode('|', $allowList).')';
            } else {
                $allowList = null;
            }
        }

        $this->allowList = $allowList;
    }

    public function isTargetAllowed(string $targetUrl): bool
    {
        if (null === $this->allowList || '' === $this->allowList) {
            return false;
        }

        $host = parse_url($targetUrl, \PHP_URL_HOST);

        if (!\is_string($host)) {
            throw new \InvalidArgumentException(\sprintf('Url "%s" does not contain a host name.', $targetUrl));
        }

        return preg_match('{^'.$this->allowList.'$}i', $host) > 0;
    }
}
