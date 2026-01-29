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

namespace Nelmio\SecurityBundle\Test;

use Nelmio\SecurityBundle\Test\Constraint\ResponseHasContentSecurityPolicy;
use Nelmio\SecurityBundle\Test\Constraint\ResponseHasContentTypeOptions;
use Nelmio\SecurityBundle\Test\Constraint\ResponseHasCrossOriginEmbedderPolicy;
use Nelmio\SecurityBundle\Test\Constraint\ResponseHasCrossOriginOpenerPolicy;
use Nelmio\SecurityBundle\Test\Constraint\ResponseHasCrossOriginResourcePolicy;
use Nelmio\SecurityBundle\Test\Constraint\ResponseHasFrameOptions;
use Nelmio\SecurityBundle\Test\Constraint\ResponseHasReferrerPolicy;
use Nelmio\SecurityBundle\Test\Constraint\ResponseHasStrictTransportSecurity;

/**
 * Trait providing assertions to verify HTTP security headers.
 *
 * This trait can be used in any PHPUnit test case that extends WebTestCase.
 *
 * Usage:
 *
 * ```php
 * use Nelmio\SecurityBundle\Test\SecurityHeadersAssertionsTrait;
 * use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
 *
 * class MyControllerTest extends WebTestCase
 * {
 *     use SecurityHeadersAssertionsTrait;
 *
 *     public function testHomepageHasSecurityHeaders(): void
 *     {
 *         $client = static::createClient([], ['HTTPS' => 'on']);
 *         $client->request('GET', '/');
 *
 *         static::assertIsIsolated();
 *     }
 * }
 * ```
 */
trait SecurityHeadersAssertionsTrait
{
    /**
     * Assert Cross-Origin-Resource-Policy header is correctly set.
     */
    public static function assertCrossOriginResourcePolicy(
        string $expected = 'same-origin',
        string $message = ''
    ): void {
        self::assertThatForResponse(new ResponseHasCrossOriginResourcePolicy($expected), $message);
    }

    /**
     * Assert Cross-Origin-Embedder-Policy header is correctly set.
     */
    public static function assertCrossOriginEmbedderPolicy(
        string $expected = 'require-corp',
        string $message = ''
    ): void {
        self::assertThatForResponse(new ResponseHasCrossOriginEmbedderPolicy($expected), $message);
    }

    /**
     * Assert Cross-Origin-Opener-Policy header is correctly set.
     */
    public static function assertCrossOriginOpenerPolicy(
        string $expected = 'same-origin',
        string $message = ''
    ): void {
        self::assertThatForResponse(new ResponseHasCrossOriginOpenerPolicy($expected), $message);
    }

    /**
     * Assert all Cross-Origin headers (CORP, COEP, COOP) are correctly set.
     */
    public static function assertCrossOriginHeaders(string $corp, string $coep, string $coop): void
    {
        static::assertCrossOriginResourcePolicy($corp);
        static::assertCrossOriginEmbedderPolicy($coep);
        static::assertCrossOriginOpenerPolicy($coop);
    }

    /**
     * Assert the response is properly isolated for cross-origin isolation.
     *
     * This verifies that all three cross-origin headers are set with strict values:
     * - Cross-Origin-Resource-Policy: same-origin
     * - Cross-Origin-Embedder-Policy: require-corp
     * - Cross-Origin-Opener-Policy: same-origin
     *
     * These headers enable powerful features like SharedArrayBuffer and high-precision timers.
     */
    public static function assertIsIsolated(): void
    {
        static::assertCrossOriginHeaders('same-origin', 'require-corp', 'same-origin');
    }

    /**
     * Assert Content-Security-Policy header is present and optionally validate its content.
     *
     * @param string[]|null $requiredDirectives Directives that must be present (e.g., ['default-src', 'script-src'])
     * @param bool          $reportOnly         Check Content-Security-Policy-Report-Only instead
     * @param string[]      $contains           Values that must be present (e.g., ["'self'", "https://example.com"])
     * @param string[]      $notContains        Values that must NOT be present (e.g., ["'unsafe-inline'", "'unsafe-eval'"])
     * @param string        $message            Custom failure message
     */
    public static function assertCspHeader(
        ?array $requiredDirectives = null,
        bool $reportOnly = false,
        array $contains = [],
        array $notContains = [],
        string $message = ''
    ): void {
        self::assertThatForResponse(
            new ResponseHasContentSecurityPolicy($requiredDirectives, $reportOnly, $contains, $notContains),
            $message
        );
    }

    /**
     * Assert X-Frame-Options header is correctly set.
     */
    public static function assertFrameOptions(
        string $expected = 'DENY',
        string $message = ''
    ): void {
        self::assertThatForResponse(new ResponseHasFrameOptions($expected), $message);
    }

    /**
     * Assert X-Content-Type-Options header is set to nosniff.
     */
    public static function assertContentTypeOptions(string $message = ''): void
    {
        self::assertThatForResponse(new ResponseHasContentTypeOptions(), $message);
    }

    /**
     * Assert Referrer-Policy header is correctly set.
     *
     * @param string[] $expected Expected policies (e.g., ['no-referrer', 'strict-origin-when-cross-origin'])
     */
    public static function assertReferrerPolicy(
        array $expected = ['no-referrer', 'strict-origin-when-cross-origin'],
        string $message = ''
    ): void {
        self::assertThatForResponse(new ResponseHasReferrerPolicy($expected), $message);
    }

    /**
     * Assert Strict-Transport-Security header is correctly configured.
     */
    public static function assertStrictTransportSecurity(
        int $maxAge = 31536000,
        bool $includeSubDomains = true,
        bool $preload = true,
        string $message = ''
    ): void {
        self::assertThatForResponse(
            new ResponseHasStrictTransportSecurity($maxAge, $includeSubDomains, $preload),
            $message
        );
    }
}
