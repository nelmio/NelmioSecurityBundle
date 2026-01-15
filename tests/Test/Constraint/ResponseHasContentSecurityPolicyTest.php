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

namespace Nelmio\SecurityBundle\Tests\Test\Constraint;

use Nelmio\SecurityBundle\Test\Constraint\ResponseHasContentSecurityPolicy;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Response;

final class ResponseHasContentSecurityPolicyTest extends TestCase
{
    public function testMatchesWithHeader(): void
    {
        $response = new Response();
        $response->headers->set('Content-Security-Policy', "default-src 'self'");

        $constraint = new ResponseHasContentSecurityPolicy();

        $this->assertTrue($constraint->evaluate($response, '', true));
    }

    public function testMatchesWithRequiredDirectives(): void
    {
        $response = new Response();
        $response->headers->set('Content-Security-Policy', "default-src 'self'; script-src 'self'");

        $constraint = new ResponseHasContentSecurityPolicy(['default-src', 'script-src']);

        $this->assertTrue($constraint->evaluate($response, '', true));
    }

    public function testDoesNotMatchWithMissingDirective(): void
    {
        $response = new Response();
        $response->headers->set('Content-Security-Policy', "default-src 'self'");

        $constraint = new ResponseHasContentSecurityPolicy(['default-src', 'script-src']);

        $this->assertFalse($constraint->evaluate($response, '', true));
    }

    public function testDoesNotMatchWithMissingHeader(): void
    {
        $response = new Response();

        $constraint = new ResponseHasContentSecurityPolicy();

        $this->assertFalse($constraint->evaluate($response, '', true));
    }

    public function testDoesNotMatchWithEmptyHeader(): void
    {
        $response = new Response();
        $response->headers->set('Content-Security-Policy', '');

        $constraint = new ResponseHasContentSecurityPolicy();

        $this->assertFalse($constraint->evaluate($response, '', true));
    }

    public function testReportOnlyHeader(): void
    {
        $response = new Response();
        $response->headers->set('Content-Security-Policy-Report-Only', "default-src 'self'");

        $constraint = new ResponseHasContentSecurityPolicy(null, true);

        $this->assertTrue($constraint->evaluate($response, '', true));
    }

    public function testReportOnlyWithRequiredDirectives(): void
    {
        $response = new Response();
        $response->headers->set('Content-Security-Policy-Report-Only', "default-src 'self'; script-src 'self'");

        $constraint = new ResponseHasContentSecurityPolicy(['default-src', 'script-src'], true);

        $this->assertTrue($constraint->evaluate($response, '', true));
    }

    public function testToStringWithoutDirectives(): void
    {
        $constraint = new ResponseHasContentSecurityPolicy();

        $this->assertSame('has Content-Security-Policy header', $constraint->toString());
    }

    public function testToStringWithDirectives(): void
    {
        $constraint = new ResponseHasContentSecurityPolicy(['default-src', 'script-src']);

        $this->assertSame(
            'has Content-Security-Policy header with directives: default-src, script-src',
            $constraint->toString()
        );
    }

    public function testToStringReportOnly(): void
    {
        $constraint = new ResponseHasContentSecurityPolicy(null, true);

        $this->assertSame('has Content-Security-Policy-Report-Only header', $constraint->toString());
    }

    public function testContainsValue(): void
    {
        $response = new Response();
        $response->headers->set('Content-Security-Policy', "default-src 'self'; script-src 'self' https://example.com");

        $constraint = new ResponseHasContentSecurityPolicy(null, false, ["'self'", 'https://example.com']);

        $this->assertTrue($constraint->evaluate($response, '', true));
    }

    public function testContainsValueFails(): void
    {
        $response = new Response();
        $response->headers->set('Content-Security-Policy', "default-src 'self'");

        $constraint = new ResponseHasContentSecurityPolicy(null, false, ['https://example.com']);

        $this->assertFalse($constraint->evaluate($response, '', true));
    }

    public function testNotContainsValue(): void
    {
        $response = new Response();
        $response->headers->set('Content-Security-Policy', "default-src 'self'; script-src 'self'");

        $constraint = new ResponseHasContentSecurityPolicy(null, false, [], ["'unsafe-inline'", "'unsafe-eval'"]);

        $this->assertTrue($constraint->evaluate($response, '', true));
    }

    public function testNotContainsValueFails(): void
    {
        $response = new Response();
        $response->headers->set('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'");

        $constraint = new ResponseHasContentSecurityPolicy(null, false, [], ["'unsafe-inline'"]);

        $this->assertFalse($constraint->evaluate($response, '', true));
    }

    public function testCombinedContainsAndNotContains(): void
    {
        $response = new Response();
        $response->headers->set('Content-Security-Policy', "default-src 'self'; script-src 'self' https://cdn.example.com");

        $constraint = new ResponseHasContentSecurityPolicy(
            ['default-src', 'script-src'],
            false,
            ["'self'", 'https://cdn.example.com'],
            ["'unsafe-inline'", "'unsafe-eval'"]
        );

        $this->assertTrue($constraint->evaluate($response, '', true));
    }

    public function testToStringWithContains(): void
    {
        $constraint = new ResponseHasContentSecurityPolicy(null, false, ["'self'"]);

        $this->assertSame(
            "has Content-Security-Policy header with containing: 'self'",
            $constraint->toString()
        );
    }

    public function testToStringWithNotContains(): void
    {
        $constraint = new ResponseHasContentSecurityPolicy(null, false, [], ["'unsafe-inline'"]);

        $this->assertSame(
            "has Content-Security-Policy header with not containing: 'unsafe-inline'",
            $constraint->toString()
        );
    }

    public function testToStringWithAllOptions(): void
    {
        $constraint = new ResponseHasContentSecurityPolicy(
            ['default-src'],
            false,
            ["'self'"],
            ["'unsafe-inline'"]
        );

        $this->assertSame(
            "has Content-Security-Policy header with directives: default-src; containing: 'self'; not containing: 'unsafe-inline'",
            $constraint->toString()
        );
    }
}
