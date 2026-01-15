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

use Nelmio\SecurityBundle\Test\Constraint\ResponseHasCrossOriginOpenerPolicy;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Response;

final class ResponseHasCrossOriginOpenerPolicyTest extends TestCase
{
    public function testMatchesWithCorrectHeader(): void
    {
        $response = new Response();
        $response->headers->set('Cross-Origin-Opener-Policy', 'same-origin');

        $constraint = new ResponseHasCrossOriginOpenerPolicy('same-origin');

        $this->assertTrue($constraint->evaluate($response, '', true));
    }

    public function testMatchesWithDefaultValue(): void
    {
        $response = new Response();
        $response->headers->set('Cross-Origin-Opener-Policy', 'same-origin');

        $constraint = new ResponseHasCrossOriginOpenerPolicy();

        $this->assertTrue($constraint->evaluate($response, '', true));
    }

    public function testDoesNotMatchWithDifferentValue(): void
    {
        $response = new Response();
        $response->headers->set('Cross-Origin-Opener-Policy', 'unsafe-none');

        $constraint = new ResponseHasCrossOriginOpenerPolicy('same-origin');

        $this->assertFalse($constraint->evaluate($response, '', true));
    }

    public function testDoesNotMatchWithMissingHeader(): void
    {
        $response = new Response();

        $constraint = new ResponseHasCrossOriginOpenerPolicy('same-origin');

        $this->assertFalse($constraint->evaluate($response, '', true));
    }

    public function testToString(): void
    {
        $constraint = new ResponseHasCrossOriginOpenerPolicy('same-origin');

        $this->assertSame(
            'has Cross-Origin-Opener-Policy header set to "same-origin"',
            $constraint->toString()
        );
    }

    public function testSameOriginAllowPopupsValue(): void
    {
        $response = new Response();
        $response->headers->set('Cross-Origin-Opener-Policy', 'same-origin-allow-popups');

        $constraint = new ResponseHasCrossOriginOpenerPolicy('same-origin-allow-popups');

        $this->assertTrue($constraint->evaluate($response, '', true));
    }

    public function testNoopenerAllowPopupsValue(): void
    {
        $response = new Response();
        $response->headers->set('Cross-Origin-Opener-Policy', 'noopener-allow-popups');

        $constraint = new ResponseHasCrossOriginOpenerPolicy('noopener-allow-popups');

        $this->assertTrue($constraint->evaluate($response, '', true));
    }
}
