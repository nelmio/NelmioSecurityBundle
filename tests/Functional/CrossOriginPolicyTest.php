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

namespace Nelmio\SecurityBundle\Tests\Functional;

use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

final class CrossOriginPolicyTest extends WebTestCase
{
    /**
     * @dataProvider providePathsAndExpectedHeaders
     */
    public function testPathSpecificHeaders(string $path, ?string $expectedCoep, ?string $expectedCoop, ?string $expectedCorp): void
    {
        $client = static::createClient();

        $client->request('GET', $path);

        $response = $client->getResponse();

        if (null !== $expectedCoep) {
            $this->assertResponseHeaderSame('cross-origin-embedder-policy', $expectedCoep);
        } else {
            $this->assertFalse($response->headers->has('cross-origin-embedder-policy'));
        }

        if (null !== $expectedCoop) {
            $this->assertResponseHeaderSame('cross-origin-opener-policy', $expectedCoop);
        } else {
            $this->assertFalse($response->headers->has('cross-origin-opener-policy'));
        }

        if (null !== $expectedCorp) {
            $this->assertResponseHeaderSame('cross-origin-resource-policy', $expectedCorp);
        } else {
            $this->assertFalse($response->headers->has('cross-origin-resource-policy'));
        }
    }

    /**
     * @return iterable<string, array{string, string|null, string|null, string|null}>
     */
    public static function providePathsAndExpectedHeaders(): iterable
    {
        // Test /admin path - most specific, should match first
        yield 'admin path' => [
            '/admin',
            'require-corp',
            'same-origin',
            'same-origin',
        ];

        yield 'admin subpath' => [
            '/admin/users',
            'require-corp',
            'same-origin',
            'same-origin',
        ];

        // Test /api path - only coep and corp defined
        yield 'api path' => [
            '/api',
            'unsafe-none',
            null,
            'cross-origin',
        ];

        yield 'api subpath' => [
            '/api/v1/users',
            'unsafe-none',
            null,
            'cross-origin',
        ];

        // Test /articles path - only coop defined
        yield 'articles path' => [
            '/articles',
            null,
            'same-origin-allow-popups',
            null,
        ];

        yield 'articles subpath' => [
            '/articles/123',
            null,
            'same-origin-allow-popups',
            null,
        ];

        // Test default path - should match any other path
        yield 'root path' => [
            '/',
            'credentialless',
            'same-origin',
            'cross-origin',
        ];

        yield 'other path' => [
            '/other/path',
            'credentialless',
            'same-origin',
            'cross-origin',
        ];
    }

    public function testReportOnlyMode(): void
    {
        $client = static::createClient();

        // Test that report-only headers are used instead
        $client->request('GET', '/test-report-only');

        $response = $client->getResponse();

        // Should use Report-Only headers
        $this->assertResponseHeaderSame('cross-origin-embedder-policy-report-only', 'require-corp');
        $this->assertResponseHeaderSame('cross-origin-opener-policy-report-only', 'same-origin');
        $this->assertFalse($response->headers->has('cross-origin-embedder-policy'));
        $this->assertFalse($response->headers->has('cross-origin-opener-policy'));
    }

    public function testReportToEndpoint(): void
    {
        $client = static::createClient();

        // Test that report-to parameter is added
        $client->request('GET', '/test-report-to');

        $response = $client->getResponse();

        $this->assertResponseHeaderSame('cross-origin-embedder-policy', 'require-corp; report-to="coi-endpoint"');
        $this->assertResponseHeaderSame('cross-origin-opener-policy', 'same-origin; report-to="coi-endpoint"');
    }

    public function testReportOnlyWithReportTo(): void
    {
        $client = static::createClient();

        // Test combination of report-only + report-to
        $client->request('GET', '/test-report-combined');

        $response = $client->getResponse();

        $this->assertResponseHeaderSame('cross-origin-embedder-policy-report-only', 'require-corp; report-to="coi-endpoint"');
        $this->assertResponseHeaderSame('cross-origin-opener-policy-report-only', 'same-origin; report-to="coi-endpoint"');
    }
}
