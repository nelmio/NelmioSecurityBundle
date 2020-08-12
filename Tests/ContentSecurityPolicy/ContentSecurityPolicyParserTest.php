<?php

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

        $sourceList = array($source);
        $result = $parser->parseSourceList($sourceList);
        $this->assertEquals($expected, $result, 'CSP parser should quote CSP keywords');
    }

    public function keywordsProvider()
    {
        return array(
            array('self', "'self'"),
            array('unsafe-inline', "'unsafe-inline'"),
            array('unsafe-eval', "'unsafe-eval'"),
            array('unsafe-hashes', "'unsafe-hashes'"),
            array('strict-dynamic', "'strict-dynamic'"),
            array('report-sample', "'report-sample'"),
            array('unsafe-allow-redirects', "'unsafe-allow-redirects'"),
            array('none', "'none'"),
            array('hostname', 'hostname'),
            array('example.com', 'example.com'),
            array('http://example.com', 'http://example.com'),
            array('http://example.com:81', 'http://example.com:81'),
            array('https://example.com', 'https://example.com'),
            array("script", "'script'"),
            array("style", "'style'")
        );
    }
}
