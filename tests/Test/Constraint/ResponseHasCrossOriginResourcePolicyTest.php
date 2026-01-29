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

use Nelmio\SecurityBundle\Test\Constraint\ResponseHasCrossOriginResourcePolicy;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Response;

final class ResponseHasCrossOriginResourcePolicyTest extends TestCase
{
    public function testMatchesWithCorrectHeader(): void
    {
        $response = new Response();
        $response->headers->set('Cross-Origin-Resource-Policy', 'same-origin');

        $constraint = new ResponseHasCrossOriginResourcePolicy('same-origin');

        $this->assertTrue($constraint->evaluate($response, '', true));
    }

    public function testMatchesWithDefaultValue(): void
    {
        $response = new Response();
        $response->headers->set('Cross-Origin-Resource-Policy', 'same-origin');

        $constraint = new ResponseHasCrossOriginResourcePolicy();

        $this->assertTrue($constraint->evaluate($response, '', true));
    }

    public function testDoesNotMatchWithDifferentValue(): void
    {
        $response = new Response();
        $response->headers->set('Cross-Origin-Resource-Policy', 'cross-origin');

        $constraint = new ResponseHasCrossOriginResourcePolicy('same-origin');

        $this->assertFalse($constraint->evaluate($response, '', true));
    }

    public function testDoesNotMatchWithMissingHeader(): void
    {
        $response = new Response();

        $constraint = new ResponseHasCrossOriginResourcePolicy('same-origin');

        $this->assertFalse($constraint->evaluate($response, '', true));
    }

    public function testToString(): void
    {
        $constraint = new ResponseHasCrossOriginResourcePolicy('same-origin');

        $this->assertSame(
            'has Cross-Origin-Resource-Policy header set to "same-origin"',
            $constraint->toString()
        );
    }

    public function testSameSiteValue(): void
    {
        $response = new Response();
        $response->headers->set('Cross-Origin-Resource-Policy', 'same-site');

        $constraint = new ResponseHasCrossOriginResourcePolicy('same-site');

        $this->assertTrue($constraint->evaluate($response, '', true));
    }

    public function testCrossOriginValue(): void
    {
        $response = new Response();
        $response->headers->set('Cross-Origin-Resource-Policy', 'cross-origin');

        $constraint = new ResponseHasCrossOriginResourcePolicy('cross-origin');

        $this->assertTrue($constraint->evaluate($response, '', true));
    }
}
