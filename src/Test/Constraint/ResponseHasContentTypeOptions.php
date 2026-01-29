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

final class ResponseHasContentTypeOptions extends Constraint
{
    public function toString(): string
    {
        return 'has X-Content-Type-Options header set to "nosniff"';
    }

    /**
     * @param mixed $other
     */
    protected function matches($other): bool
    {
        if (!$other instanceof Response) {
            return false;
        }

        if (!$other->headers->has('X-Content-Type-Options')) {
            return false;
        }

        return 'nosniff' === $other->headers->get('X-Content-Type-Options');
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

        if (!$other->headers->has('X-Content-Type-Options')) {
            return 'X-Content-Type-Options header is missing';
        }

        return \sprintf(
            'X-Content-Type-Options header is "%s" instead of "nosniff"',
            $other->headers->get('X-Content-Type-Options')
        );
    }
}
