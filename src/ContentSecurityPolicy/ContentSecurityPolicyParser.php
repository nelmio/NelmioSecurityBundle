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

class ContentSecurityPolicyParser
{
    protected $keywords = array(
        'self',
        'unsafe-inline',
        'unsafe-eval',
        'wasm-unsafe-eval',
        'strict-dynamic',
        'unsafe-hashes',
        'report-sample',
        'unsafe-allow-redirects',
        'none',
    );

    /**
     * @param array $sourceList
     *
     * @return string
     */
    public function parseSourceList($sourceList)
    {
        if (!is_array($sourceList)) {
            return $sourceList;
        }

        $sourceList = $this->quoteKeywords($sourceList);

        return implode(' ', $sourceList);
    }

    /**
     * @param array $sourceList
     *
     * @return array
     */
    protected function quoteKeywords(array $sourceList)
    {
        $keywords = $this->keywords;

        return array_map(
            function ($source) use ($keywords) {
                if (in_array($source, $keywords, true)) {
                    return sprintf("'%s'", $source);
                }

                return $source;
            },
            $sourceList
        );
    }
}
