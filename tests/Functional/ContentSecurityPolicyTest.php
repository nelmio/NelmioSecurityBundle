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

final class ContentSecurityPolicyTest extends WebTestCase
{
    public function testHeaders(): void
    {
        $client = static::createClient();

        $client->request('GET', '/');

        $this->assertResponseIsSuccessful();
        self::assertResponseHeaderSame(
            'content-security-policy',
            "default-src 'self'; block-all-mixed-content; frame-src https://www.youtube.com; img-src 'self' facebook.com flickr.com; script-src 'self' 'unsafe-inline'; report-uri /nelmio/csp/report"
        );
        self::assertResponseHeaderSame(
            'x-content-security-policy',
            "default-src 'self'; block-all-mixed-content; frame-src https://www.youtube.com; img-src 'self' facebook.com flickr.com; script-src 'self' 'unsafe-inline'; report-uri /nelmio/csp/report"
        );
        self::assertResponseHeaderSame(
            'content-security-policy-report-only',
            "script-src 'self'; report-uri /nelmio/csp/report"
        );
        self::assertResponseHeaderSame(
            'x-content-security-policy-report-only',
            "script-src 'self'; report-uri /nelmio/csp/report"
        );
    }

    /**
     * @dataProvider provideInvalidRequests
     */
    public function testPostReportWithInvalidRequests(?string $content, int $statusCode, string $errorContent): void
    {
        $client = static::createClient();

        $client->request('POST', '/csp/report', [], [], [], $content);

        $this->assertResponseStatusCodeSame($statusCode);
        $this->assertSame($errorContent, $client->getResponse()->getContent());
    }

    public function provideInvalidRequests(): iterable
    {
        yield 'without data' => [null, 411, 'Content-Security-Policy Endpoint called without data'];
        yield 'invalid JSON' => ['invalid_json', 400, 'Content-Security-Policy Endpoint called with invalid JSON data'];
        yield 'JSON without csp-report' => [json_encode(['no_csp']), 400, 'Content-Security-Policy Endpoint called without "csp-report" data'];
    }

    public function testPostReportFiltered(): void
    {
        $client = static::createClient();

        $client->request('POST', '/csp/report', [], [], [], json_encode(['csp-report' => [
            'blocked-uri' => 'translate.google.com',
        ]]));

        $this->assertResponseStatusCodeSame(204);
        $this->assertSame('', $client->getResponse()->getContent());
    }

    public function testPostReport(): void
    {
        $client = static::createClient();

        $client->request('POST', '/csp/report', [], [], [], json_encode(['csp-report' => []]));

        $this->assertResponseStatusCodeSame(204);
        $this->assertSame('', $client->getResponse()->getContent());
    }
}
