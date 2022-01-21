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

namespace Nelmio\SecurityBundle\Tests\ContentSecurityPolicy\Violation;

use Nelmio\SecurityBundle\ContentSecurityPolicy\Violation\Filter\BrowserBugsNoiseDetector;
use Nelmio\SecurityBundle\ContentSecurityPolicy\Violation\Filter\DomainsNoiseDetector;
use Nelmio\SecurityBundle\ContentSecurityPolicy\Violation\Filter\DomainsRegexNoiseDetector;
use Nelmio\SecurityBundle\ContentSecurityPolicy\Violation\Filter\Filter;
use Nelmio\SecurityBundle\ContentSecurityPolicy\Violation\Filter\InjectedScriptsNoiseDetector;
use Nelmio\SecurityBundle\ContentSecurityPolicy\Violation\Filter\SchemesNoiseDetector;
use Nelmio\SecurityBundle\ContentSecurityPolicy\Violation\Report;
use Symfony\Component\HttpFoundation\Request;
use UAParser\Parser;

class FilterTest extends \PHPUnit\Framework\TestCase
{
    /**
     * @dataProvider provideVariousCases
     */
    public function testScenario($expected, $request, $payload)
    {
        $filter = new Filter();
        $filter->addNoiseDetector(new BrowserBugsNoiseDetector(Parser::create()));
        $filter->addNoiseDetector(new DomainsNoiseDetector());
        $filter->addNoiseDetector(new DomainsRegexNoiseDetector());
        $filter->addNoiseDetector(new InjectedScriptsNoiseDetector());
        $filter->addNoiseDetector(new SchemesNoiseDetector());

        $this->assertSame($expected, $filter->filter($request, new Report($payload)));
    }

    public function provideVariousCases()
    {
        $firefox42 = new Request();
        $firefox42->headers->set('user-agent', 'Mozilla/5.0 (X11; Linux x86_64; rv:42.0) Gecko/20100101 Firefox/42.0');

        $iceweasel38 = new Request();
        $iceweasel38->headers->set('user-agent', 'Mozilla/5.0 (X11; Linux x86_64; rv:38.0) Gecko/20100101 Firefox/38.0 Iceweasel/38.7.1');

        $ff43mobile = new Request();
        $ff43mobile->headers->set('user-agent', 'Mozilla/5.0 (Android 4.1.1; Tablet; rv:43.0) Gecko/43.0 Firefox/43.0');

        $firefox43 = new Request();
        $firefox43->headers->set('user-agent', 'Mozilla/5.0 (X11; Linux x86_64; rv:42.0) Gecko/20100101 Firefox/43.0');

        $firefox49 = new Request();
        $firefox49->headers->set('user-agent', 'Mozilla/5.0 (X11; Linux x86_64; rv:42.0) Gecko/20100101 Firefox/49.0');

        return [
            [true, new Request(), [
                'blocked-uri' => 'https://static.cmptch.com',
                'effective-directive' => 'script-src',
            ]],
            [false, new Request(), [
                'blocked-uri' => 'https://google.com',
                'effective-directive' => 'connect-src',
            ]],
            [true, new Request(), [
                'blocked-uri' => 'https://partners.cmptch.com',
                'effective-directive' => 'script-src',
            ]],
            [true, new Request(), [
                'blocked-uri' => 'https://partners.cmptch.com',
                'effective-directive' => 'object-src',
            ]],
            [true, new Request(), [
                'blocked-uri' => 'https://d144fqpiyasmrr.cloudfront.net/uploads/picture/59582.png',
                'effective-directive' => 'img-src',
            ]],
            [true, new Request(), [
                'blocked-uri' => 'https://cdncache-a.akamaihd.net',
                'effective-directive' => 'font-src',
            ]],
            [true, new Request(), [
                'blocked-uri' => 'https://i_vrtumcjs_info.tlscdn.com',
                'effective-directive' => 'script-src',
            ]],
            [true, new Request(), [
                'blocked-uri' => 'https://i_vrtumcjs_info.tlscdn.com/path/to/script.js',
                'effective-directive' => 'script-src',
            ]],
            [true, new Request(), [
                'blocked-uri' => 'https://d2x1jgnvxlnz25.cloudfront.net',
                'effective-directive' => 'media-src',
            ]],
            [true, new Request(), [
                'blocked-uri' => 'http://d2x1jgnvxlnz25.cloudfront.net',
                'effective-directive' => 'media-src',
            ]],
            [true, new Request(), [
                'blocked-uri' => 'd2x1jgnvxlnz25.cloudfront.net',
                'effective-directive' => 'media-src',
            ]],
            [true, new Request(), [
                'blocked-uri' => 'https://nikkomsgchannel',
                'effective-directive' => 'connect-src',
            ]],
            [true, new Request(), [
                'blocked-uri' => 'nikkomsgchannel',
                'effective-directive' => 'connect-src',
            ]],
            [true, new Request(), [
                'blocked-uri' => 'https://query.jollywallet.com',
                'violated-directive' => 'script-src https://domain.com',
            ]],
            [true, new Request(), [
                'blocked-uri' => 'https://query.jollywallet.com',
                'effective-directive' => 'script-src',
            ]],
            [true, new Request(), [
                'blocked-uri' => 'https://api.jollywallet.com',
                'effective-directive' => 'script-src',
            ]],
            [true, new Request(), [
                'source-file' => 'safari-extension://org.adblockplus.adblockplussafari-gryyzr985a',
                'effective-directive' => 'script-src',
            ]],
            [true, new Request(), [
                'blocked-uri' => 'self',
                'effective-directive' => 'script-src',
                'script-sample' => 'try {  for(var lastpass_iter=0; lastpass',
            ]],
            [true, new Request(), [
                'blocked-uri' => 'self',
                'effective-directive' => 'script-src',
                'script-sample' => '(function () {

        var event_id = docum',
            ]],
            [true, new Request(), [
                'blocked-uri' => 'self',
                'effective-directive' => 'script-src',
                'script-sample' => 'try {
window.AG_onLoad = function(func)',
            ]],
            [true, new Request(), [
                'blocked-uri' => 'self',
                'effective-directive' => 'script-src',
                'script-sample' => 'var BlockAdBlock = function ()',
            ]],
            [true, new Request(), [
                'blocked-uri' => 'self',
                'effective-directive' => 'script-src',
                'script-sample' => 'var FuckAdBlock = function ()',
            ]],
            [true, new Request(), [
                'blocked-uri' => 'self',
                'effective-directive' => 'script-src',
                'script-sample' => "\n ;(function installGlobalHook(window) {",
            ]],
            [true, $firefox42, [
                'blocked-uri' => 'self',
                'effective-directive' => 'script-src',
            ]],
            [true, $firefox42, [
                'blocked-uri' => 'about',
                'effective-directive' => 'base-uri',
            ]],
            [true, $firefox42, [
                'blocked-uri' => 'about:blank',
                'effective-directive' => 'base-uri',
            ]],
            [true, $iceweasel38, [
                'blocked-uri' => 'about:blank',
                'effective-directive' => 'base-uri',
            ]],
            [true, $ff43mobile, [
                'blocked-uri' => 'about:blank',
                'effective-directive' => 'base-uri',
            ]],
            [false, $firefox43, [
                'blocked-uri' => 'self',
                'effective-directive' => 'script-src',
            ]],
            [false, $firefox49, [
                'blocked-uri' => 'about:blank',
                'effective-directive' => 'base-uri',
            ]],
            [true, new Request(), [
                'blocked-uri' => 'ms-appx-web://',
                'effective-directive' => 'script-src',
            ]],
            [true, new Request(), [
                'blocked-uri' => 'weixinping',
                'effective-directive' => 'script-src',
            ]],
            [true, new Request(), [
                'blocked-uri' => 'ms-browser-extension',
                'effective-directive' => 'script-src',
            ]],
            [true, new Request(), [
                'blocked-uri' => 'sraf://img',
                'effective-directive' => 'img-src',
            ]],
        ];
    }
}
