<?php

/*
 * This file is part of the Nelmio SecurityBundle.
 *
 * (c) Nelmio <hello@nelm.io>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Nelmio\SecurityBundle\Tests\ContentSecurityPolicy;

use Nelmio\SecurityBundle\ContentSecurityPolicy\ContentSecurityPolicyParser;

class ContentSecurityPolicyParserTest extends \PHPUnit\Framework\TestCase
{
    /**
     * @dataProvider keywordsProvider
     */
    public function testQuotesKeywords($source, $expected)
    {
        $parser = new ContentSecurityPolicyParser();

        $sourceList = [$source];
        $result = $parser->parseSourceList($sourceList);
        $this->assertEquals($expected, $result, 'CSP parser should quote CSP keywords');
    }

    public function keywordsProvider()
    {
        return [
            ['self', "'self'"],
            ['unsafe-inline', "'unsafe-inline'"],
            ['unsafe-eval', "'unsafe-eval'"],
            ['unsafe-hashes', "'unsafe-hashes'"],
            ['strict-dynamic', "'strict-dynamic'"],
            ['report-sample', "'report-sample'"],
            ['unsafe-allow-redirects', "'unsafe-allow-redirects'"],
            ['none', "'none'"],
            ['hostname', 'hostname'],
            ['example.com', 'example.com'],
            ['http://example.com', 'http://example.com'],
            ['http://example.com:81', 'http://example.com:81'],
            ['https://example.com', 'https://example.com'],
        ];
    }
}
