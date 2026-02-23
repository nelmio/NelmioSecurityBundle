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

use Nelmio\SecurityBundle\Test\Constraint\ResponseHasContentTypeOptions;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Response;

final class ResponseHasContentTypeOptionsTest extends TestCase
{
    public function testMatchesWithCorrectHeader(): void
    {
        $response = new Response();
        $response->headers->set('X-Content-Type-Options', 'nosniff');

        $constraint = new ResponseHasContentTypeOptions();

        $this->assertTrue($constraint->evaluate($response, '', true));
    }

    public function testDoesNotMatchWithDifferentValue(): void
    {
        $response = new Response();
        $response->headers->set('X-Content-Type-Options', 'other');

        $constraint = new ResponseHasContentTypeOptions();

        $this->assertFalse($constraint->evaluate($response, '', true));
    }

    public function testDoesNotMatchWithMissingHeader(): void
    {
        $response = new Response();

        $constraint = new ResponseHasContentTypeOptions();

        $this->assertFalse($constraint->evaluate($response, '', true));
    }

    public function testToString(): void
    {
        $constraint = new ResponseHasContentTypeOptions();

        $this->assertSame('has X-Content-Type-Options header set to "nosniff"', $constraint->toString());
    }
}
