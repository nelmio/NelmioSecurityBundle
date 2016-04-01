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
                'script-src script.example.org \'self\'; '.
                'object-src object.example.org \'self\'; '.
                'style-src style.example.org \'self\'; '.
                'img-src img.example.org \'self\'; '.
                'media-src media.example.org \'self\'; '.
                'frame-src frame.example.org \'self\'; '.
                'font-src font.example.org \'self\'; '.
                'connect-src connect.example.org \'self\'; '.
                'report-uri http://report-uri; '.
                'base-uri base-uri.example.org \'self\'; '.
                'child-src child-src.example.org \'self\'; '.
                'form-action form-action.example.org \'self\'; '.
                'frame-ancestors frame-ancestors.example.org \'self\'; '.
                'plugin-types application/shockwave-flash; '.
                'block-all-mixed-content; '.
                'upgrade-insecure-requests',
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
                'script-src script.example.org \'self\'; '.
                'object-src object.example.org \'self\'; '.
                'style-src style.example.org \'self\'; '.
                'img-src img.example.org \'self\'; '.
                'media-src media.example.org \'self\'; '.
                'frame-src frame.example.org \'self\'; '.
                'font-src font.example.org \'self\'; '.
                'connect-src connect.example.org \'self\'; '.
                'report-uri http://report-uri; '.
                'base-uri base-uri.example.org \'self\'; '.
                'child-src child-src.example.org \'self\'; '.
                'form-action form-action.example.org \'self\'; '.
                'frame-ancestors frame-ancestors.example.org \'self\'; '.
                'plugin-types application/shockwave-flash',
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
                'script-src script.example.org \'self\'; '.
                'object-src object.example.org \'self\'; '.
                'style-src style.example.org \'self\'; '.
                'img-src img.example.org \'self\'; '.
                'media-src media.example.org \'self\'; '.
                'frame-src frame.example.org \'self\'; '.
                'font-src font.example.org \'self\'; '.
                'connect-src connect.example.org \'self\'; '.
                'report-uri http://report-uri; '.
                'base-uri base-uri.example.org \'self\'; '.
                'child-src child-src.example.org \'self\'; '.
                'form-action form-action.example.org \'self\'; '.
                'frame-ancestors frame-ancestors.example.org \'self\'; '.
                'plugin-types application/shockwave-flash',
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
                'plugin-types \'none\'',
                array(
                    'default-src' => array('none'),
                    'plugin-types' => array('none'),
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
        $this->assertSame($expected, $directive->buildHeaderValueWithInlineSignatures($signatures));
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
