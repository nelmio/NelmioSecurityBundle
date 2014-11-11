<?php

namespace Nelmio\SecurityBundle\Tests\ContentSecurityPolicy;

use Nelmio\SecurityBundle\ContentSecurityPolicy\ContentSecurityPolicyParser;

class ContentSecurityPolicyParserTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @dataProvider keywordsProvider
     */
    public function testQuotesKeywords($source, $expected)
    {
        $parser = new ContentSecurityPolicyParser();

        $sourceList = array($source);
        $result     = $parser->parseSourceList($sourceList);
        $this->assertEquals($expected, $result, 'CSP parser should quote CSP keywords');
    }

    public function keywordsProvider()
    {
        return array(
            array('self', "'self'"),
            array('none', "'none'"),
            array('unsafe-eval', "'unsafe-eval'"),
            array('unsafe-inline', "'unsafe-inline'"),
            array('hostname', 'hostname'),
            array('example.com', 'example.com'),
            array('http://example.com', 'http://example.com'),
            array('http://example.com:81', 'http://example.com:81'),
            array('https://example.com', 'https://example.com'),
        );
    }
}
