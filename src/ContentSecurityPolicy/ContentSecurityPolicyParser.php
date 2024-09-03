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

final class ContentSecurityPolicyParser
{
    /**
     * @var list<string>
     */
    private array $keywords = [
        'self',
        'unsafe-inline',
        'unsafe-eval',
        'wasm-unsafe-eval',
        'strict-dynamic',
        'unsafe-hashes',
        'report-sample',
        'unsafe-allow-redirects',
        'none',
    ];

    /**
     * @param list<string>|true $sourceList
     *
     * @return string|true
     */
    public function parseSourceList($sourceList)
    {
        if (!\is_array($sourceList)) {
            return $sourceList;
        }

        $sourceList = $this->quoteKeywords($sourceList);

        return implode(' ', $sourceList);
    }

    /**
     * @param list<string> $sourceList
     *
     * @return list<string>
     */
    private function quoteKeywords(array $sourceList): array
    {
        $keywords = $this->keywords;

        return array_map(
            static function (string $source) use ($keywords) {
                if (\in_array($source, $keywords, true)) {
                    return \sprintf("'%s'", $source);
                }

                return $source;
            },
            $sourceList
        );
    }
}
