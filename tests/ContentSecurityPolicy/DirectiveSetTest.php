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

namespace Nelmio\SecurityBundle\Tests\ContentSecurityPolicy;

use Nelmio\SecurityBundle\ContentSecurityPolicy\DirectiveSet;
use Nelmio\SecurityBundle\ContentSecurityPolicy\PolicyManager;
use Nelmio\SecurityBundle\UserAgent\UAFamilyParser\UAFamilyParser;
use Nelmio\SecurityBundle\UserAgent\UserAgentParser;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use UAParser\Parser;

class DirectiveSetTest extends TestCase
{
    private const UA_CHROME = 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36';
    private const UA_SAFARI = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12) AppleWebKit/602.1.18 (KHTML, like Gecko) Version/9.2 Safari/602.1.18';
    private const UA_FIREFOX = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.11; rv:45.0) Gecko/20100101 Firefox/45.0';
    private const UA_OPERA = 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2490.86 Safari/537.36 OPR/33.0.1990.115';
    private const UA_IE = 'Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko';

    /**
     * @dataProvider provideVariousConfig
     *
     * @param array<string, list<string>|true> $directives
     */
    public function testFromConfig(string $expected, string $ua, array $directives): void
    {
        $ds = DirectiveSet::fromConfig($this->createPolicyManager(), ['enforce' => array_merge(['level1_fallback' => true], $directives)], 'enforce');

        $request = new Request();
        $request->headers->set('user-agent', $ua);
        $this->assertSame($expected, $ds->buildHeaderValue($request));
    }

    public static function provideVariousConfig(): array
    {
        return [
            [
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
                'report-uri http://report-uri; '.
                'worker-src worker.example.com \'self\'; '.
                'report-to csp-endpoint',
                self::UA_CHROME,
                [
                    'default-src' => ['example.org', "'self'"],
                    'script-src' => ['script.example.org', "'self'"],
                    'object-src' => ['object.example.org', "'self'"],
                    'style-src' => ['style.example.org', "'self'"],
                    'img-src' => ['img.example.org', "'self'"],
                    'manifest-src' => ['manifest.example.org', "'self'"],
                    'media-src' => ['media.example.org', "'self'"],
                    'frame-src' => ['frame.example.org', "'self'"],
                    'font-src' => ['font.example.org', "'self'"],
                    'connect-src' => ['connect.example.org', "'self'"],
                    'worker-src' => ['worker.example.com', "'self'"],
                    'report-uri' => ['http://report-uri'],
                    'report-to' => 'csp-endpoint',
                    'base-uri' => ['base-uri.example.org', "'self'"],
                    'child-src' => ['child-src.example.org', "'self'"],
                    'form-action' => ['form-action.example.org', "'self'"],
                    'frame-ancestors' => ['frame-ancestors.example.org', "'self'"],
                    'plugin-types' => ['application/shockwave-flash'],
                    'block-all-mixed-content' => true,
                    'upgrade-insecure-requests' => true,
                ],
            ],

            [
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
                'report-uri http://report-uri; '.
                'worker-src worker.example.com \'self\'; '.
                'report-to csp-endpoint',
                self::UA_FIREFOX,
                [
                    'default-src' => ['example.org', "'self'"],
                    'script-src' => ['script.example.org', "'self'"],
                    'object-src' => ['object.example.org', "'self'"],
                    'style-src' => ['style.example.org', "'self'"],
                    'img-src' => ['img.example.org', "'self'"],
                    'media-src' => ['media.example.org', "'self'"],
                    'manifest-src' => ['manifest.example.org', "'self'"],
                    'frame-src' => ['frame.example.org', "'self'"],
                    'font-src' => ['font.example.org', "'self'"],
                    'connect-src' => ['connect.example.org', "'self'"],
                    'worker-src' => ['worker.example.com', "'self'"],
                    'report-uri' => ['http://report-uri'],
                    'report-to' => 'csp-endpoint',
                    'base-uri' => ['base-uri.example.org', "'self'"],
                    'child-src' => ['child-src.example.org', "'self'"],
                    'form-action' => ['form-action.example.org', "'self'"],
                    'frame-ancestors' => ['frame-ancestors.example.org', "'self'"],
                    'plugin-types' => ['application/shockwave-flash'],
                    'block-all-mixed-content' => true,
                    'upgrade-insecure-requests' => true,
                ],
            ],

            [
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
                'report-uri http://report-uri; '.
                'worker-src worker.example.com \'self\'; '.
                'report-to csp-endpoint',
                self::UA_IE,
                [
                    'default-src' => ['example.org', "'self'"],
                    'script-src' => ['script.example.org', "'self'"],
                    'object-src' => ['object.example.org', "'self'"],
                    'style-src' => ['style.example.org', "'self'"],
                    'img-src' => ['img.example.org', "'self'"],
                    'media-src' => ['media.example.org', "'self'"],
                    'frame-src' => ['frame.example.org', "'self'"],
                    'font-src' => ['font.example.org', "'self'"],
                    'connect-src' => ['connect.example.org', "'self'"],
                    'worker-src' => ['worker.example.com', "'self'"],
                    'report-uri' => ['http://report-uri'],
                    'report-to' => 'csp-endpoint',
                    'base-uri' => ['base-uri.example.org', "'self'"],
                    'child-src' => ['child-src.example.org', "'self'"],
                    'form-action' => ['form-action.example.org', "'self'"],
                    'frame-ancestors' => ['frame-ancestors.example.org', "'self'"],
                    'plugin-types' => ['application/shockwave-flash'],
                    'block-all-mixed-content' => true,
                    'upgrade-insecure-requests' => true,
                ],
            ],

            [
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
                'report-uri http://report-uri; '.
                'worker-src worker.example.com \'self\'; '.
                'report-to csp-endpoint',
                self::UA_OPERA,
                [
                    'default-src' => ['example.org', "'self'"],
                    'script-src' => ['script.example.org', "'self'"],
                    'object-src' => ['object.example.org', "'self'"],
                    'style-src' => ['style.example.org', "'self'"],
                    'img-src' => ['img.example.org', "'self'"],
                    'manifest-src' => ['media.example.org', "'self'"],
                    'media-src' => ['media.example.org', "'self'"],
                    'frame-src' => ['frame.example.org', "'self'"],
                    'font-src' => ['font.example.org', "'self'"],
                    'connect-src' => ['connect.example.org', "'self'"],
                    'worker-src' => ['worker.example.com', "'self'"],
                    'report-uri' => ['http://report-uri'],
                    'report-to' => 'csp-endpoint',
                    'base-uri' => ['base-uri.example.org', "'self'"],
                    'child-src' => ['child-src.example.org', "'self'"],
                    'form-action' => ['form-action.example.org', "'self'"],
                    'frame-ancestors' => ['frame-ancestors.example.org', "'self'"],
                    'plugin-types' => ['application/shockwave-flash'],
                    'block-all-mixed-content' => true,
                    'upgrade-insecure-requests' => true,
                ],
            ],

            [
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
                [
                    'default-src' => ['example.org', "'self'"],
                    'script-src' => ['script.example.org', "'self'"],
                    'object-src' => ['object.example.org', "'self'"],
                    'style-src' => ['style.example.org', "'self'"],
                    'img-src' => ['img.example.org', "'self'"],
                    'media-src' => ['media.example.org', "'self'"],
                    'frame-src' => ['frame.example.org', "'self'"],
                    'font-src' => ['font.example.org', "'self'"],
                    'connect-src' => ['connect.example.org', "'self'"],
                    'worker-src' => ['worker.example.com', "'self'"],
                    'report-uri' => ['http://report-uri'],
                    'report-to' => 'csp-endpoint',
                    'base-uri' => ['base-uri.example.org', "'self'"],
                    'child-src' => ['child-src.example.org', "'self'"],
                    'form-action' => ['form-action.example.org', "'self'"],
                    'frame-ancestors' => ['frame-ancestors.example.org', "'self'"],
                    'plugin-types' => ['application/shockwave-flash'],
                    'block-all-mixed-content' => true,
                    'upgrade-insecure-requests' => true,
                ],
            ],

            [
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
                'report-uri http://report-uri; '.
                'worker-src worker.example.com \'self\'; '.
                'report-to csp-endpoint',
                self::UA_CHROME,
                [
                    'default-src' => ['example.org', "'self'"],
                    'script-src' => ['script.example.org', "'self'"],
                    'object-src' => ['object.example.org', "'self'"],
                    'style-src' => ['style.example.org', "'self'"],
                    'img-src' => ['img.example.org', "'self'"],
                    'media-src' => ['media.example.org', "'self'"],
                    'frame-src' => ['frame.example.org', "'self'"],
                    'font-src' => ['font.example.org', "'self'"],
                    'connect-src' => ['connect.example.org', "'self'"],
                    'worker-src' => ['worker.example.com', "'self'"],
                    'report-uri' => ['http://report-uri'],
                    'report-to' => 'csp-endpoint',
                    'base-uri' => ['base-uri.example.org', "'self'"],
                    'child-src' => ['child-src.example.org', "'self'"],
                    'form-action' => ['form-action.example.org', "'self'"],
                    'frame-ancestors' => ['frame-ancestors.example.org', "'self'"],
                    'plugin-types' => ['application/shockwave-flash'],
                    'block-all-mixed-content' => false,
                    'upgrade-insecure-requests' => false,
                ],
            ],

            [
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
                'report-uri http://report-uri; '.
                'worker-src worker.example.com \'self\'',
                self::UA_CHROME,
                [
                    'default-src' => ['example.org', "'self'"],
                    'script-src' => ['script.example.org', "'self'"],
                    'object-src' => ['object.example.org', "'self'"],
                    'style-src' => ['style.example.org', "'self'"],
                    'img-src' => ['img.example.org', "'self'"],
                    'media-src' => ['media.example.org', "'self'"],
                    'frame-src' => ['frame.example.org', "'self'"],
                    'font-src' => ['font.example.org', "'self'"],
                    'connect-src' => ['connect.example.org', "'self'"],
                    'worker-src' => ['worker.example.com', "'self'"],
                    'report-uri' => ['http://report-uri'],
                    'base-uri' => ['base-uri.example.org', "'self'"],
                    'child-src' => ['child-src.example.org', "'self'"],
                    'form-action' => ['form-action.example.org', "'self'"],
                    'frame-ancestors' => ['frame-ancestors.example.org', "'self'"],
                    'plugin-types' => ['application/shockwave-flash'],
                ],
            ],

            [
                'default-src \'none\'; '.
                'base-uri \'none\'; '.
                'form-action \'none\'; '.
                'plugin-types \'none\'',
                self::UA_CHROME,
                [
                    'default-src' => ['none'],
                    'plugin-types' => ['none'],
                    'base-uri' => ['none'],
                    'form-action' => ['none'],
                ],
            ],
            [
                'default-src \'none\'; '.
                'report-uri /csp/report1 /csp/report2',
                self::UA_CHROME,
                [
                    'default-src' => ['none'],
                    'report-uri' => ['/csp/report1', '/csp/report2'],
                ],
            ],
        ];
    }

    /**
     * @dataProvider provideConfigAndSignatures
     *
     * @param array<string, list<string>> $signatures
     *
     * @phpstan-param array<string, array{
     *     enforce?: array<string, mixed>,
     *     report?: array<string, mixed>,
     * }> $config
     */
    public function testBuildHeaderValueWithInlineSignatures(string $expected, array $config, array $signatures): void
    {
        $directive = DirectiveSet::fromConfig(new PolicyManager(), $config, 'enforce');
        $this->assertSame($expected, $directive->buildHeaderValue(new Request(), $signatures));
    }

    public static function provideConfigAndSignatures(): array
    {
        return [
            [
                'default-src \'self\'; script-src \'self\' \'unsafe-inline\' \'sha-1\'; style-src \'self\' \'unsafe-inline\' \'sha2\'',
                [
                    'enforce' => [
                        'level1_fallback' => true,
                        'default-src' => ["'self'"],
                        'script-src' => ["'self'", "'unsafe-inline'"],
                        'style-src' => [],
                    ],
                ],
                [
                    'script-src' => ['sha-1'],
                    'style-src' => ['sha2'],
                ],
            ],
            [
                'default-src yolo; script-src yolo \'unsafe-inline\' \'sha-1\'; style-src yolo \'unsafe-inline\' \'sha2\'',
                [
                    'enforce' => [
                        'level1_fallback' => true,
                        'default-src' => ['yolo'],
                    ],
                ],
                [
                    'script-src' => ['sha-1'],
                    'style-src' => ['sha2'],
                ],
            ],
            [
                'default-src \'self\'; script-src \'self\' \'unsafe-inline\' \'sha-1\'; style-src \'self\' \'unsafe-inline\' \'sha2\'',
                [
                    'enforce' => [
                        'level1_fallback' => true,
                        'default-src' => ["'self'"],
                        'script-src' => ["'self'"],
                        'style-src' => [],
                    ],
                ],
                [
                    'script-src' => ['sha-1'],
                    'style-src' => ['sha2'],
                ],
            ],
            [
                'default-src \'self\'; script-src \'self\' \'sha-1\'; style-src \'self\' \'sha2\'',
                [
                    'enforce' => [
                        'level1_fallback' => false,
                        'default-src' => ["'self'"],
                        'script-src' => ["'self'"],
                        'style-src' => [],
                    ],
                ],
                [
                    'script-src' => ['sha-1'],
                    'style-src' => ['sha2'],
                ],
            ],
        ];
    }

    private function createPolicyManager(): PolicyManager
    {
        return new PolicyManager(new UserAgentParser(new UAFamilyParser(Parser::create())));
    }
}
