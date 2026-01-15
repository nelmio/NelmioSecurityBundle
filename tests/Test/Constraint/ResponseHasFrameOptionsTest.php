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

use Nelmio\SecurityBundle\Test\Constraint\ResponseHasFrameOptions;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Response;

final class ResponseHasFrameOptionsTest extends TestCase
{
    public function testMatchesWithCorrectHeader(): void
    {
        $response = new Response();
        $response->headers->set('X-Frame-Options', 'DENY');

        $constraint = new ResponseHasFrameOptions('DENY');

        $this->assertTrue($constraint->evaluate($response, '', true));
    }

    public function testMatchesWithDefaultValue(): void
    {
        $response = new Response();
        $response->headers->set('X-Frame-Options', 'DENY');

        $constraint = new ResponseHasFrameOptions();

        $this->assertTrue($constraint->evaluate($response, '', true));
    }

    public function testDoesNotMatchWithDifferentValue(): void
    {
        $response = new Response();
        $response->headers->set('X-Frame-Options', 'SAMEORIGIN');

        $constraint = new ResponseHasFrameOptions('DENY');

        $this->assertFalse($constraint->evaluate($response, '', true));
    }

    public function testDoesNotMatchWithMissingHeader(): void
    {
        $response = new Response();

        $constraint = new ResponseHasFrameOptions('DENY');

        $this->assertFalse($constraint->evaluate($response, '', true));
    }

    public function testToString(): void
    {
        $constraint = new ResponseHasFrameOptions('DENY');

        $this->assertSame('has X-Frame-Options header set to "DENY"', $constraint->toString());
    }

    public function testSameOriginValue(): void
    {
        $response = new Response();
        $response->headers->set('X-Frame-Options', 'SAMEORIGIN');

        $constraint = new ResponseHasFrameOptions('SAMEORIGIN');

        $this->assertTrue($constraint->evaluate($response, '', true));
    }
}
