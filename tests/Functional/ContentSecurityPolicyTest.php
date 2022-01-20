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
    public function testDenyHeaders(): void
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
}
