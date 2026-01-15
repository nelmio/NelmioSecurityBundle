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

namespace Nelmio\SecurityBundle\Test\Constraint;

use PHPUnit\Framework\Constraint\Constraint;
use Symfony\Component\HttpFoundation\Response;

final class ResponseHasReferrerPolicy extends Constraint
{
    /**
     * @var string[]
     */
    private $expected;

    /**
     * @param string[] $expected
     */
    public function __construct(array $expected = ['no-referrer', 'strict-origin-when-cross-origin'])
    {
        $this->expected = $expected;
    }

    public function toString(): string
    {
        return \sprintf('has Referrer-Policy header set to "%s"', implode(', ', $this->expected));
    }

    /**
     * @param mixed $other
     */
    protected function matches($other): bool
    {
        if (!$other instanceof Response) {
            return false;
        }

        if (!$other->headers->has('Referrer-Policy')) {
            return false;
        }

        $expectedValue = implode(', ', $this->expected);

        return $other->headers->get('Referrer-Policy') === $expectedValue;
    }

    /**
     * @param mixed $other
     */
    protected function failureDescription($other): string
    {
        return 'the Response '.$this->toString();
    }

    /**
     * @param mixed $other
     */
    protected function additionalFailureDescription($other): string
    {
        if (!$other instanceof Response) {
            return 'Value is not a Response object';
        }

        if (!$other->headers->has('Referrer-Policy')) {
            return 'Referrer-Policy header is missing';
        }

        return \sprintf(
            'Referrer-Policy header is "%s" instead of "%s"',
            $other->headers->get('Referrer-Policy'),
            implode(', ', $this->expected)
        );
    }
}
