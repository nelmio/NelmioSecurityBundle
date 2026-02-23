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

final class ResponseHasStrictTransportSecurity extends Constraint
{
    /**
     * @var int
     */
    private $maxAge;

    /**
     * @var bool
     */
    private $includeSubDomains;

    /**
     * @var bool
     */
    private $preload;

    public function __construct(int $maxAge = 31536000, bool $includeSubDomains = true, bool $preload = true)
    {
        $this->maxAge = $maxAge;
        $this->includeSubDomains = $includeSubDomains;
        $this->preload = $preload;
    }

    public function toString(): string
    {
        return 'has Strict-Transport-Security header properly configured';
    }

    /**
     * @param mixed $other
     */
    protected function matches($other): bool
    {
        if (!$other instanceof Response) {
            return false;
        }

        if (!$other->headers->has('Strict-Transport-Security')) {
            return false;
        }

        $headerValue = $other->headers->get('Strict-Transport-Security');

        if (null === $headerValue) {
            return false;
        }

        // Check max-age
        if (false === strpos($headerValue, \sprintf('max-age=%d', $this->maxAge))) {
            return false;
        }

        // Check includeSubDomains
        if ($this->includeSubDomains && false === strpos($headerValue, 'includeSubDomains')) {
            return false;
        }

        // Check preload
        if ($this->preload && false === strpos($headerValue, 'preload')) {
            return false;
        }

        return true;
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

        if (!$other->headers->has('Strict-Transport-Security')) {
            return 'Strict-Transport-Security header is missing';
        }

        $headerValue = $other->headers->get('Strict-Transport-Security');

        if (null === $headerValue) {
            return 'Strict-Transport-Security header is empty';
        }

        $issues = [];

        if (false === strpos($headerValue, \sprintf('max-age=%d', $this->maxAge))) {
            $issues[] = \sprintf('max-age should be %d', $this->maxAge);
        }

        if ($this->includeSubDomains && false === strpos($headerValue, 'includeSubDomains')) {
            $issues[] = 'should include includeSubDomains';
        }

        if ($this->preload && false === strpos($headerValue, 'preload')) {
            $issues[] = 'should include preload';
        }

        return \sprintf(
            'Strict-Transport-Security header is "%s" but %s',
            $headerValue,
            implode(', ', $issues)
        );
    }
}
