<?php

/*
 * This file is part of the Nelmio SecurityBundle.
 *
 * (c) Nelmio <hello@nelm.io>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Nelmio\SecurityBundle\UserAgent\UAFamilyParser;

use Doctrine\Common\Cache\Cache;

class DoctrineCacheUAFamilyParser implements UAFamilyParserInterface
{
    private $cache;
    private $parser;
    private $lifetime;
    private $prefix;

    public function __construct(Cache $cache, UAFamilyParser $parser, $lifetime = 0, $prefix = 'nelmio-ua-parser-')
    {
        $this->parser = $parser;
        $this->cache = $cache;
        $this->lifetime = $lifetime;
        $this->prefix = $prefix;
    }

    public function getUaFamily($userAgent)
    {
        $id = $this->prefix.md5($userAgent);

        if (false !== $name = $this->cache->fetch($id)) {
            return $name;
        }

        $name = $this->parser->getUaFamily($userAgent);

        $this->cache->save($id, $name, $this->lifetime);

        return $name;
    }
}
