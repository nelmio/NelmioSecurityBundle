<?php

namespace Nelmio\SecurityBundle\Tests\ContentSecurityPolicy;

use Nelmio\SecurityBundle\ContentSecurityPolicy\DirectiveSet;
use Nelmio\SecurityBundle\ContentSecurityPolicy\PolicyManager;
use Nelmio\SecurityBundle\UserAgent\UAFamilyParser\UAFamilyParser;
use Nelmio\SecurityBundle\UserAgent\UserAgentParser;
use Symfony\Component\HttpFoundation\Request;
use UAParser\Parser;

class DirectiveSetTest extends \PHPUnit_Framework_TestCase
{
    const UA_CHROME = 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36';
    const UA_SAFARI = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12) AppleWebKit/602.1.18 (KHTML, like Gecko) Version/9.2 Safari/602.1.18';
    const UA_FIREFOX = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.11; rv:45.0) Gecko/20100101 Firefox/45.0';
    const UA_OPERA = 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2490.86 Safari/537.36 OPR/33.0.1990.115';
    const UA_IE = 'Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko';

    /**
     * @dataProvider provideVariousConfig
     */
    public function testFromConfig($expected, $ua, array $directives)
    {
        $ds = DirectiveSet::fromConfig($this->createPolicyManager(), array('enforce' => array_merge(array('level1_fallback' => true), $directives)), 'enforce');

        $request = new Request();
        $request->headers->set('user-agent', $ua);
        $this->assertSame($expected, $ds->buildHeaderValue($request));
    }

    private function createPolicyManager()
    {
        return new PolicyManager(new UserAgentParser(new UAFamilyParser(Parser::create())));
    }

    public function provideVariousConfig()
    {
        return array(
            array(
                'default-src example.org \'self\'; '.
                'base-uri base-uri.example.org \'self\'; '.
                'block-all-mixed-content; '.
                'child-src child-src.example.org \'self\'; '.
                'connect-src connect.example.org \'self\'; '.
                'font-src font.example.org \'self\'; '.
                'form-action form-action.example.org \'self\'; '.
                'frame-ancestors frame-ancestors.example.org \'self\'; '.
                'frame-src frame.example.org \'self\'; '.
                'img-src img.example.org \'self\'; '.
                'manifest-src manifest.example.org \'self\'; '.
                'media-src media.example.org \'self\'; '.
                'object-src object.example.org \'self\'; '.
                'plugin-types application/shockwave-flash; '.
                'script-src script.example.org \'self\'; '.
                'style-src style.example.org \'self\'; '.
                'upgrade-insecure-requests; '.
                'report-uri http://report-uri',
                self::UA_CHROME,
                array(
                    'default-src' => array('example.org', "'self'"),
                    'script-src' => array('script.example.org', "'self'"),
                    'object-src' => array('object.example.org', "'self'"),
                    'style-src' => array('style.example.org', "'self'"),
                    'img-src' => array('img.example.org', "'self'"),
                    'manifest-src' => array('manifest.example.org', "'self'"),
                    'media-src' => array('media.example.org', "'self'"),
                    'frame-src' => array('frame.example.org', "'self'"),
                    'font-src' => array('font.example.org', "'self'"),
                    'connect-src' => array('connect.example.org', "'self'"),
                    'report-uri' => array('http://report-uri'),
                    'base-uri' => array('base-uri.example.org', "'self'"),
                    'child-src' => array('child-src.example.org', "'self'"),
                    'form-action' => array('form-action.example.org', "'self'"),
                    'frame-ancestors' => array('frame-ancestors.example.org', "'self'"),
                    'plugin-types' => array('application/shockwave-flash'),
                    'block-all-mixed-content' => true,
                    'upgrade-insecure-requests' => true,
                ),
            ),

            array(
                'default-src example.org \'self\'; '.
                'base-uri base-uri.example.org \'self\'; '.
                'connect-src connect.example.org \'self\'; '.
                'font-src font.example.org \'self\'; '.
                'form-action form-action.example.org \'self\'; '.
                'frame-ancestors frame-ancestors.example.org \'self\'; '.
                'frame-src frame.example.org \'self\'; '.
                'img-src img.example.org \'self\'; '.
                'manifest-src manifest.example.org \'self\'; '.
                'media-src media.example.org \'self\'; '.
                'object-src object.example.org \'self\'; '.
                'script-src script.example.org \'self\'; '.
                'style-src style.example.org \'self\'; '.
                'upgrade-insecure-requests; '.
                'report-uri http://report-uri',
                self::UA_FIREFOX,
                array(
                    'default-src' => array('example.org', "'self'"),
                    'script-src' => array('script.example.org', "'self'"),
                    'object-src' => array('object.example.org', "'self'"),
                    'style-src' => array('style.example.org', "'self'"),
                    'img-src' => array('img.example.org', "'self'"),
                    'media-src' => array('media.example.org', "'self'"),
                    'manifest-src' => array('manifest.example.org', "'self'"),
                    'frame-src' => array('frame.example.org', "'self'"),
                    'font-src' => array('font.example.org', "'self'"),
                    'connect-src' => array('connect.example.org', "'self'"),
                    'report-uri' => array('http://report-uri'),
                    'base-uri' => array('base-uri.example.org', "'self'"),
                    'child-src' => array('child-src.example.org', "'self'"),
                    'form-action' => array('form-action.example.org', "'self'"),
                    'frame-ancestors' => array('frame-ancestors.example.org', "'self'"),
                    'plugin-types' => array('application/shockwave-flash'),
                    'block-all-mixed-content' => true,
                    'upgrade-insecure-requests' => true,
                ),
            ),

            array(
                'default-src example.org \'self\'; '.
                'base-uri base-uri.example.org \'self\'; '.
                'block-all-mixed-content; '.
                'child-src child-src.example.org \'self\'; '.
                'connect-src connect.example.org \'self\'; '.
                'font-src font.example.org \'self\'; '.
                'form-action form-action.example.org \'self\'; '.
                'frame-ancestors frame-ancestors.example.org \'self\'; '.
                'frame-src frame.example.org \'self\'; '.
                'img-src img.example.org \'self\'; '.
                'media-src media.example.org \'self\'; '.
                'object-src object.example.org \'self\'; '.
                'plugin-types application/shockwave-flash; '.
                'script-src script.example.org \'self\'; '.
                'style-src style.example.org \'self\'; '.
                'upgrade-insecure-requests; '.
                'report-uri http://report-uri',
                self::UA_IE,
                array(
                    'default-src' => array('example.org', "'self'"),
                    'script-src' => array('script.example.org', "'self'"),
                    'object-src' => array('object.example.org', "'self'"),
                    'style-src' => array('style.example.org', "'self'"),
                    'img-src' => array('img.example.org', "'self'"),
                    'media-src' => array('media.example.org', "'self'"),
                    'frame-src' => array('frame.example.org', "'self'"),
                    'font-src' => array('font.example.org', "'self'"),
                    'connect-src' => array('connect.example.org', "'self'"),
                    'report-uri' => array('http://report-uri'),
                    'base-uri' => array('base-uri.example.org', "'self'"),
                    'child-src' => array('child-src.example.org', "'self'"),
                    'form-action' => array('form-action.example.org', "'self'"),
                    'frame-ancestors' => array('frame-ancestors.example.org', "'self'"),
                    'plugin-types' => array('application/shockwave-flash'),
                    'block-all-mixed-content' => true,
                    'upgrade-insecure-requests' => true,
                ),
            ),

            array(
                'default-src example.org \'self\'; '.
                'base-uri base-uri.example.org \'self\'; '.
                'block-all-mixed-content; '.
                'child-src child-src.example.org \'self\'; '.
                'connect-src connect.example.org \'self\'; '.
                'font-src font.example.org \'self\'; '.
                'form-action form-action.example.org \'self\'; '.
                'frame-ancestors frame-ancestors.example.org \'self\'; '.
                'frame-src frame.example.org \'self\'; '.
                'img-src img.example.org \'self\'; '.
                'manifest-src media.example.org \'self\'; '.
                'media-src media.example.org \'self\'; '.
                'object-src object.example.org \'self\'; '.
                'plugin-types application/shockwave-flash; '.
                'script-src script.example.org \'self\'; '.
                'style-src style.example.org \'self\'; '.
                'upgrade-insecure-requests; '.
                'report-uri http://report-uri',
                self::UA_OPERA,
                array(
                    'default-src' => array('example.org', "'self'"),
                    'script-src' => array('script.example.org', "'self'"),
                    'object-src' => array('object.example.org', "'self'"),
                    'style-src' => array('style.example.org', "'self'"),
                    'img-src' => array('img.example.org', "'self'"),
                    'manifest-src' => array('media.example.org', "'self'"),
                    'media-src' => array('media.example.org', "'self'"),
                    'frame-src' => array('frame.example.org', "'self'"),
                    'font-src' => array('font.example.org', "'self'"),
                    'connect-src' => array('connect.example.org', "'self'"),
                    'report-uri' => array('http://report-uri'),
                    'base-uri' => array('base-uri.example.org', "'self'"),
                    'child-src' => array('child-src.example.org', "'self'"),
                    'form-action' => array('form-action.example.org', "'self'"),
                    'frame-ancestors' => array('frame-ancestors.example.org', "'self'"),
                    'plugin-types' => array('application/shockwave-flash'),
                    'block-all-mixed-content' => true,
                    'upgrade-insecure-requests' => true,
                ),
            ),

            array(
                'default-src example.org \'self\'; '.
                'connect-src connect.example.org \'self\'; '.
                'font-src font.example.org \'self\'; '.
                'frame-src frame.example.org \'self\'; '.
                'img-src img.example.org \'self\'; '.
                'media-src media.example.org \'self\'; '.
                'object-src object.example.org \'self\'; '.
                'script-src script.example.org \'self\'; '.
                'style-src style.example.org \'self\'; '.
                'report-uri http://report-uri',
                self::UA_SAFARI,
                array(
                    'default-src' => array('example.org', "'self'"),
                    'script-src' => array('script.example.org', "'self'"),
                    'object-src' => array('object.example.org', "'self'"),
                    'style-src' => array('style.example.org', "'self'"),
                    'img-src' => array('img.example.org', "'self'"),
                    'media-src' => array('media.example.org', "'self'"),
                    'frame-src' => array('frame.example.org', "'self'"),
                    'font-src' => array('font.example.org', "'self'"),
                    'connect-src' => array('connect.example.org', "'self'"),
                    'report-uri' => array('http://report-uri'),
                    'base-uri' => array('base-uri.example.org', "'self'"),
                    'child-src' => array('child-src.example.org', "'self'"),
                    'form-action' => array('form-action.example.org', "'self'"),
                    'frame-ancestors' => array('frame-ancestors.example.org', "'self'"),
                    'plugin-types' => array('application/shockwave-flash'),
                    'block-all-mixed-content' => true,
                    'upgrade-insecure-requests' => true,
                ),
            ),

            array(
                'default-src example.org \'self\'; '.
                'base-uri base-uri.example.org \'self\'; '.
                'child-src child-src.example.org \'self\'; '.
                'connect-src connect.example.org \'self\'; '.
                'font-src font.example.org \'self\'; '.
                'form-action form-action.example.org \'self\'; '.
                'frame-ancestors frame-ancestors.example.org \'self\'; '.
                'frame-src frame.example.org \'self\'; '.
                'img-src img.example.org \'self\'; '.
                'media-src media.example.org \'self\'; '.
                'object-src object.example.org \'self\'; '.
                'plugin-types application/shockwave-flash; '.
                'script-src script.example.org \'self\'; '.
                'style-src style.example.org \'self\'; '.
                'report-uri http://report-uri',
                self::UA_CHROME,
                array(
                    'default-src' => array('example.org', "'self'"),
                    'script-src' => array('script.example.org', "'self'"),
                    'object-src' => array('object.example.org', "'self'"),
                    'style-src' => array('style.example.org', "'self'"),
                    'img-src' => array('img.example.org', "'self'"),
                    'media-src' => array('media.example.org', "'self'"),
                    'frame-src' => array('frame.example.org', "'self'"),
                    'font-src' => array('font.example.org', "'self'"),
                    'connect-src' => array('connect.example.org', "'self'"),
                    'report-uri' => array('http://report-uri'),
                    'base-uri' => array('base-uri.example.org', "'self'"),
                    'child-src' => array('child-src.example.org', "'self'"),
                    'form-action' => array('form-action.example.org', "'self'"),
                    'frame-ancestors' => array('frame-ancestors.example.org', "'self'"),
                    'plugin-types' => array('application/shockwave-flash'),
                    'block-all-mixed-content' => false,
                    'upgrade-insecure-requests' => false,
                ),
            ),

            array(
                'default-src example.org \'self\'; '.
                'base-uri base-uri.example.org \'self\'; '.
                'child-src child-src.example.org \'self\'; '.
                'connect-src connect.example.org \'self\'; '.
                'font-src font.example.org \'self\'; '.
                'form-action form-action.example.org \'self\'; '.
                'frame-ancestors frame-ancestors.example.org \'self\'; '.
                'frame-src frame.example.org \'self\'; '.
                'img-src img.example.org \'self\'; '.
                'media-src media.example.org \'self\'; '.
                'object-src object.example.org \'self\'; '.
                'plugin-types application/shockwave-flash; '.
                'script-src script.example.org \'self\'; '.
                'style-src style.example.org \'self\'; '.
                'report-uri http://report-uri',
                self::UA_CHROME,
                array(
                    'default-src' => array('example.org', "'self'"),
                    'script-src' => array('script.example.org', "'self'"),
                    'object-src' => array('object.example.org', "'self'"),
                    'style-src' => array('style.example.org', "'self'"),
                    'img-src' => array('img.example.org', "'self'"),
                    'media-src' => array('media.example.org', "'self'"),
                    'frame-src' => array('frame.example.org', "'self'"),
                    'font-src' => array('font.example.org', "'self'"),
                    'connect-src' => array('connect.example.org', "'self'"),
                    'report-uri' => array('http://report-uri'),
                    'base-uri' => array('base-uri.example.org', "'self'"),
                    'child-src' => array('child-src.example.org', "'self'"),
                    'form-action' => array('form-action.example.org', "'self'"),
                    'frame-ancestors' => array('frame-ancestors.example.org', "'self'"),
                    'plugin-types' => array('application/shockwave-flash'),
                ),
            ),

            array(
                'default-src \'none\'; '.
                'base-uri \'none\'; '.
                'form-action \'none\'; '.
                'plugin-types \'none\'',
                self::UA_CHROME,
                array(
                    'default-src' => array('none'),
                    'plugin-types' => array('none'),
                    'base-uri' => array('none'),
                    'form-action' => array('none'),
                ),
            ),
            array(
                'default-src \'none\'; '.
                'report-uri /csp/report1 /csp/report2',
                self::UA_CHROME,
                array(
                    'default-src' => array('none'),
                    'report-uri' => array('/csp/report1', '/csp/report2'),
                ),
            ),
        );
    }

    /**
     * @dataProvider provideConfigAndSignatures
     */
    public function testBuildHeaderValueWithInlineSignatures($expected, $config, $signatures)
    {
        $directive = DirectiveSet::fromConfig(new PolicyManager(), $config, 'enforce');
        $this->assertSame($expected, $directive->buildHeaderValue(new Request(), $signatures));
    }

    public function provideConfigAndSignatures()
    {
        return array(
            array(
                'default-src \'self\'; script-src \'self\' \'unsafe-inline\' \'sha-1\'; style-src \'self\' \'unsafe-inline\' \'sha2\'',
                array(
                    'enforce' => array(
                        'level1_fallback' => true,
                        'default-src' => array("'self'"),
                        'script-src' => array("'self'", "'unsafe-inline'"),
                        'style-src' => array(),
                    ),
                ),
                array(
                    'script-src' => array('sha-1'),
                    'style-src' => array('sha2'),
                ),
            ),
            array(
                'default-src yolo; script-src yolo \'unsafe-inline\' \'sha-1\'; style-src yolo \'unsafe-inline\' \'sha2\'',
                array(
                    'enforce' => array(
                        'level1_fallback' => true,
                        'default-src' => array('yolo'),
                    ),
                ),
                array(
                    'script-src' => array('sha-1'),
                    'style-src' => array('sha2'),
                ),
            ),
            array(
                'default-src \'self\'; script-src \'self\' \'unsafe-inline\' \'sha-1\'; style-src \'self\' \'unsafe-inline\' \'sha2\'',
                array(
                    'enforce' => array(
                        'level1_fallback' => true,
                        'default-src' => array("'self'"),
                        'script-src' => array("'self'"),
                        'style-src' => array(),
                    ),
                ),
                array(
                    'script-src' => array('sha-1'),
                    'style-src' => array('sha2'),
                ),
            ),
            array(
                'default-src \'self\'; script-src \'self\' \'sha-1\'; style-src \'self\' \'sha2\'',
                array(
                    'enforce' => array(
                        'level1_fallback' => false,
                        'default-src' => array("'self'"),
                        'script-src' => array("'self'"),
                        'style-src' => array(),
                    ),
                ),
                array(
                    'script-src' => array('sha-1'),
                    'style-src' => array('sha2'),
                ),
            ),
        );
    }
}
