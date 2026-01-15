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

final class ResponseHasFrameOptions extends Constraint
{
    /**
     * @var string
     */
    private $expected;

    public function __construct(string $expected = 'DENY')
    {
        $this->expected = $expected;
    }

    public function toString(): string
    {
        return \sprintf('has X-Frame-Options header set to "%s"', $this->expected);
    }

    /**
     * @param mixed $other
     */
    protected function matches($other): bool
    {
        if (!$other instanceof Response) {
            return false;
        }

        if (!$other->headers->has('X-Frame-Options')) {
            return false;
        }

        return $other->headers->get('X-Frame-Options') === $this->expected;
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

        if (!$other->headers->has('X-Frame-Options')) {
            return 'X-Frame-Options header is missing';
        }

        return \sprintf(
            'X-Frame-Options header is "%s" instead of "%s"',
            $other->headers->get('X-Frame-Options'),
            $this->expected
        );
    }
}
