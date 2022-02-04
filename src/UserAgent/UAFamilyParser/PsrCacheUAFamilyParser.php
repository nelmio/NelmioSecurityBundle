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

namespace Nelmio\SecurityBundle\UserAgent\UAFamilyParser;

use Psr\Cache\CacheItemPoolInterface;

final class PsrCacheUAFamilyParser implements UAFamilyParserInterface
{
    private CacheItemPoolInterface $cache;
    private UAFamilyParserInterface $parser;
    private int $lifetime;
    private string $prefix;

    public function __construct(CacheItemPoolInterface $cache, UAFamilyParserInterface $parser, int $lifetime = 0, string $prefix = 'nelmio-ua-parser-')
    {
        $this->parser = $parser;
        $this->cache = $cache;
        $this->lifetime = $lifetime;
        $this->prefix = $prefix;
    }

    public function getUaFamily(string $userAgent): string
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
