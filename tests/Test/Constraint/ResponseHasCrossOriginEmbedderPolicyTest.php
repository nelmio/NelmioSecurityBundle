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

use Nelmio\SecurityBundle\Test\Constraint\ResponseHasCrossOriginEmbedderPolicy;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Response;

final class ResponseHasCrossOriginEmbedderPolicyTest extends TestCase
{
    public function testMatchesWithCorrectHeader(): void
    {
        $response = new Response();
        $response->headers->set('Cross-Origin-Embedder-Policy', 'require-corp');

        $constraint = new ResponseHasCrossOriginEmbedderPolicy('require-corp');

        $this->assertTrue($constraint->evaluate($response, '', true));
    }

    public function testMatchesWithDefaultValue(): void
    {
        $response = new Response();
        $response->headers->set('Cross-Origin-Embedder-Policy', 'require-corp');

        $constraint = new ResponseHasCrossOriginEmbedderPolicy();

        $this->assertTrue($constraint->evaluate($response, '', true));
    }

    public function testDoesNotMatchWithDifferentValue(): void
    {
        $response = new Response();
        $response->headers->set('Cross-Origin-Embedder-Policy', 'unsafe-none');

        $constraint = new ResponseHasCrossOriginEmbedderPolicy('require-corp');

        $this->assertFalse($constraint->evaluate($response, '', true));
    }

    public function testDoesNotMatchWithMissingHeader(): void
    {
        $response = new Response();

        $constraint = new ResponseHasCrossOriginEmbedderPolicy('require-corp');

        $this->assertFalse($constraint->evaluate($response, '', true));
    }

    public function testToString(): void
    {
        $constraint = new ResponseHasCrossOriginEmbedderPolicy('require-corp');

        $this->assertSame(
            'has Cross-Origin-Embedder-Policy header set to "require-corp"',
            $constraint->toString()
        );
    }

    public function testCredentiallessValue(): void
    {
        $response = new Response();
        $response->headers->set('Cross-Origin-Embedder-Policy', 'credentialless');

        $constraint = new ResponseHasCrossOriginEmbedderPolicy('credentialless');

        $this->assertTrue($constraint->evaluate($response, '', true));
    }
}
