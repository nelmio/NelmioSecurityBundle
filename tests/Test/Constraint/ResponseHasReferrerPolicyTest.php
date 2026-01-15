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

use Nelmio\SecurityBundle\Test\Constraint\ResponseHasReferrerPolicy;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Response;

final class ResponseHasReferrerPolicyTest extends TestCase
{
    public function testMatchesWithCorrectHeader(): void
    {
        $response = new Response();
        $response->headers->set('Referrer-Policy', 'no-referrer, strict-origin-when-cross-origin');

        $constraint = new ResponseHasReferrerPolicy(['no-referrer', 'strict-origin-when-cross-origin']);

        $this->assertTrue($constraint->evaluate($response, '', true));
    }

    public function testMatchesWithDefaultValue(): void
    {
        $response = new Response();
        $response->headers->set('Referrer-Policy', 'no-referrer, strict-origin-when-cross-origin');

        $constraint = new ResponseHasReferrerPolicy();

        $this->assertTrue($constraint->evaluate($response, '', true));
    }

    public function testDoesNotMatchWithDifferentValue(): void
    {
        $response = new Response();
        $response->headers->set('Referrer-Policy', 'no-referrer');

        $constraint = new ResponseHasReferrerPolicy(['no-referrer', 'strict-origin-when-cross-origin']);

        $this->assertFalse($constraint->evaluate($response, '', true));
    }

    public function testDoesNotMatchWithMissingHeader(): void
    {
        $response = new Response();

        $constraint = new ResponseHasReferrerPolicy();

        $this->assertFalse($constraint->evaluate($response, '', true));
    }

    public function testToString(): void
    {
        $constraint = new ResponseHasReferrerPolicy(['no-referrer', 'strict-origin-when-cross-origin']);

        $this->assertSame(
            'has Referrer-Policy header set to "no-referrer, strict-origin-when-cross-origin"',
            $constraint->toString()
        );
    }

    public function testSinglePolicy(): void
    {
        $response = new Response();
        $response->headers->set('Referrer-Policy', 'strict-origin');

        $constraint = new ResponseHasReferrerPolicy(['strict-origin']);

        $this->assertTrue($constraint->evaluate($response, '', true));
    }
}
