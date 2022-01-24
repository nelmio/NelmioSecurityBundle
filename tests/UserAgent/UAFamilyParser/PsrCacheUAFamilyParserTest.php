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

namespace Nelmio\SecurityBundle\Tests\UserAgent\UAFamilyParser;

use Nelmio\SecurityBundle\UserAgent\UAFamilyParser\PsrCacheUAFamilyParser;
use Nelmio\SecurityBundle\UserAgent\UAFamilyParser\UAFamilyParser;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Cache\Adapter\ArrayAdapter;
use UAParser\Parser;

final class PsrCacheUAFamilyParserTest extends TestCase
{
    public function testGetUaFamily(): void
    {
        $userAgent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X x.y; rv:42.0) Gecko/20100101 Firefox/42.0';
        $cacheItemPool = new ArrayAdapter();
        $uaFamilyParser = new UAFamilyParser(Parser::create());
        $family = $uaFamilyParser->getUaFamily($userAgent);

        $parser = new PsrCacheUAFamilyParser(
            $cacheItemPool,
            $uaFamilyParser,
            10
        );

        $this->assertCount(0, $cacheItemPool->getValues());
        $this->assertSame($family, $parser->getUaFamily($userAgent));
        $this->assertCount(1, $cacheItemPool->getValues());
        $this->assertSame($family, $parser->getUaFamily($userAgent));
    }
}
