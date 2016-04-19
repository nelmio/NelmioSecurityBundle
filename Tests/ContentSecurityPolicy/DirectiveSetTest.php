<?php

namespace Nelmio\SecurityBundle\Tests\ContentSecurityPolicy;

use Nelmio\SecurityBundle\ContentSecurityPolicy\DirectiveSet;

class DirectiveSetTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @dataProvider provideVariousConfig
     */
    public function testFromConfig($expected, array $directives)
    {
        $ds = DirectiveSet::fromConfig(array('enforce' => $directives, 'hash' => array('level1_fallback' => true)), 'enforce');

        $this->assertSame($expected, $ds->buildHeaderValue());
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
                'media-src media.example.org \'self\'; '.
                'object-src object.example.org \'self\'; '.
                'plugin-types application/shockwave-flash; '.
                'script-src script.example.org \'self\'; '.
                'style-src style.example.org \'self\'; '.
                'upgrade-insecure-requests; '.
                'report-uri http://report-uri',
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
        $directive = DirectiveSet::fromConfig($config, 'enforce');
        $this->assertSame($expected, $directive->buildHeaderValue($signatures));
    }

    public function provideConfigAndSignatures()
    {
        return array(
            array(
                'default-src \'self\'; script-src \'self\' \'unsafe-inline\' \'sha-1\'; style-src \'self\' \'unsafe-inline\' \'sha2\'',
                array(
                    'hash' => array('level1_fallback' => true),
                    'enforce' => array(
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
                    'hash' => array('level1_fallback' => true),
                    'enforce' => array(
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
                    'hash' => array('level1_fallback' => true),
                    'enforce' => array(
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
                    'hash' => array('level1_fallback' => false),
                    'enforce' => array(
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
