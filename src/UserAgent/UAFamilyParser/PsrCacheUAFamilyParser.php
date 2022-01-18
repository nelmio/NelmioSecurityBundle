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

use Psr\Cache\CacheItemPoolInterface;
use Psr\Cache\CacheException;

class PsrCacheUAFamilyParser implements UAFamilyParserInterface
{
    private $cache;
    private $parser;
    private $lifetime;
    private $prefix;

    public function __construct(CacheItemPoolInterface $cache, UAFamilyParser $parser, $lifetime = 0, $prefix = 'nelmio-ua-parser-')
    {
        $this->parser = $parser;
        $this->cache = $cache;
        $this->lifetime = $lifetime;
        $this->prefix = $prefix;
    }

    public function getUaFamily($userAgent)
    {
        $id = $this->prefix.md5($userAgent);

        $item = $this->cache->getItem($id);

        if ($item->isHit()) {
            return $item->get();
        }

        $name = $this->parser->getUaFamily($userAgent);

        $this->cache->save($item->set($name)->expiresAfter($this->lifetime));

        return $name;
    }
}
