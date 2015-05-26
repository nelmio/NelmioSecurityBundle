<?php

namespace Nelmio\SecurityBundle\ContentSecurityPolicy;

class ContentSecurityPolicyParser
{
    protected $keywords = array('self', 'none', 'unsafe-inline', 'unsafe-eval');

    /**
     * @param array $sourceList
     *
     * @return string
     */
    public function parseSourceList(array $sourceList)
    {
        $sourceList = $this->quoteKeywords($sourceList);

        return join(' ', $sourceList);
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
