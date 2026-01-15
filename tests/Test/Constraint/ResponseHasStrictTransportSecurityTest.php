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

use Nelmio\SecurityBundle\Test\Constraint\ResponseHasStrictTransportSecurity;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Response;

final class ResponseHasStrictTransportSecurityTest extends TestCase
{
    public function testMatchesWithCorrectHeader(): void
    {
        $response = new Response();
        $response->headers->set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');

        $constraint = new ResponseHasStrictTransportSecurity();

        $this->assertTrue($constraint->evaluate($response, '', true));
    }

    public function testMatchesWithCustomMaxAge(): void
    {
        $response = new Response();
        $response->headers->set('Strict-Transport-Security', 'max-age=86400; includeSubDomains; preload');

        $constraint = new ResponseHasStrictTransportSecurity(86400);

        $this->assertTrue($constraint->evaluate($response, '', true));
    }

    public function testDoesNotMatchWithDifferentMaxAge(): void
    {
        $response = new Response();
        $response->headers->set('Strict-Transport-Security', 'max-age=86400; includeSubDomains; preload');

        $constraint = new ResponseHasStrictTransportSecurity(31536000);

        $this->assertFalse($constraint->evaluate($response, '', true));
    }

    public function testDoesNotMatchWithMissingHeader(): void
    {
        $response = new Response();

        $constraint = new ResponseHasStrictTransportSecurity();

        $this->assertFalse($constraint->evaluate($response, '', true));
    }

    public function testDoesNotMatchWithMissingIncludeSubDomains(): void
    {
        $response = new Response();
        $response->headers->set('Strict-Transport-Security', 'max-age=31536000; preload');

        $constraint = new ResponseHasStrictTransportSecurity(31536000, true, true);

        $this->assertFalse($constraint->evaluate($response, '', true));
    }

    public function testDoesNotMatchWithMissingPreload(): void
    {
        $response = new Response();
        $response->headers->set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');

        $constraint = new ResponseHasStrictTransportSecurity(31536000, true, true);

        $this->assertFalse($constraint->evaluate($response, '', true));
    }

    public function testMatchesWithoutIncludeSubDomains(): void
    {
        $response = new Response();
        $response->headers->set('Strict-Transport-Security', 'max-age=31536000; preload');

        $constraint = new ResponseHasStrictTransportSecurity(31536000, false, true);

        $this->assertTrue($constraint->evaluate($response, '', true));
    }

    public function testMatchesWithoutPreload(): void
    {
        $response = new Response();
        $response->headers->set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');

        $constraint = new ResponseHasStrictTransportSecurity(31536000, true, false);

        $this->assertTrue($constraint->evaluate($response, '', true));
    }

    public function testMatchesMinimalHeader(): void
    {
        $response = new Response();
        $response->headers->set('Strict-Transport-Security', 'max-age=31536000');

        $constraint = new ResponseHasStrictTransportSecurity(31536000, false, false);

        $this->assertTrue($constraint->evaluate($response, '', true));
    }

    public function testToString(): void
    {
        $constraint = new ResponseHasStrictTransportSecurity();

        $this->assertSame('has Strict-Transport-Security header properly configured', $constraint->toString());
    }
}
