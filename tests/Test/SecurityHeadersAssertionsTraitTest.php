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

namespace Nelmio\SecurityBundle\Tests\Test;

use Nelmio\SecurityBundle\Test\SecurityHeadersAssertionsTrait;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

/**
 * Tests for the SecurityHeadersAssertionsTrait assertion methods.
 */
final class SecurityHeadersAssertionsTraitTest extends WebTestCase
{
    use SecurityHeadersAssertionsTrait;

    public function testAssertCrossOriginResourcePolicy(): void
    {
        $client = static::createClient();
        $client->request('GET', '/');

        // The test app config sets CORP to 'cross-origin'
        static::assertCrossOriginResourcePolicy('cross-origin');
    }

    public function testAssertCrossOriginEmbedderPolicy(): void
    {
        $client = static::createClient();
        $client->request('GET', '/');

        // The test app config sets COEP to 'credentialless'
        static::assertCrossOriginEmbedderPolicy('credentialless');
    }

    public function testAssertCrossOriginOpenerPolicy(): void
    {
        $client = static::createClient();
        $client->request('GET', '/');

        // The test app config sets COOP to 'same-origin'
        static::assertCrossOriginOpenerPolicy('same-origin');
    }

    public function testAssertCrossOriginHeaders(): void
    {
        $client = static::createClient();
        $client->request('GET', '/');

        static::assertCrossOriginHeaders('cross-origin', 'credentialless', 'same-origin');
    }

    public function testAssertContentTypeOptions(): void
    {
        $client = static::createClient();
        $client->request('GET', '/');

        static::assertContentTypeOptions();
    }

    public function testAssertReferrerPolicy(): void
    {
        $client = static::createClient();
        $client->request('GET', '/');

        static::assertReferrerPolicy(['no-referrer', 'strict-origin-when-cross-origin']);
    }

    public function testAssertCspHeader(): void
    {
        $client = static::createClient();
        $client->request('GET', '/');

        static::assertCspHeader(['default-src', 'script-src']);
    }

    public function testAssertFrameOptions(): void
    {
        $client = static::createClient();
        $client->request('GET', '/clickjacking/deny');

        static::assertFrameOptions('DENY');
    }
}
