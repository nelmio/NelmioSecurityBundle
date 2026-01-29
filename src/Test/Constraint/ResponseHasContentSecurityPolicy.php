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

final class ResponseHasContentSecurityPolicy extends Constraint
{
    /**
     * @var string[]|null
     */
    private $requiredDirectives;

    /**
     * @var bool
     */
    private $reportOnly;

    /**
     * @var string[]
     */
    private $contains;

    /**
     * @var string[]
     */
    private $notContains;

    /**
     * @param string[]|null $requiredDirectives Directives that must be present (e.g., ['default-src', 'script-src'])
     * @param bool          $reportOnly         Check Content-Security-Policy-Report-Only instead of Content-Security-Policy
     * @param string[]      $contains           Values that must be present in the CSP (e.g., ["'self'", "https://example.com"])
     * @param string[]      $notContains        Values that must NOT be present in the CSP (e.g., ["'unsafe-inline'", "'unsafe-eval'"])
     */
    public function __construct(
        ?array $requiredDirectives = null,
        bool $reportOnly = false,
        array $contains = [],
        array $notContains = []
    ) {
        $this->requiredDirectives = $requiredDirectives;
        $this->reportOnly = $reportOnly;
        $this->contains = $contains;
        $this->notContains = $notContains;
    }

    public function toString(): string
    {
        $headerName = $this->reportOnly ? 'Content-Security-Policy-Report-Only' : 'Content-Security-Policy';
        $parts = [];

        if (null !== $this->requiredDirectives) {
            $parts[] = \sprintf('directives: %s', implode(', ', $this->requiredDirectives));
        }

        if ([] !== $this->contains) {
            $parts[] = \sprintf('containing: %s', implode(', ', $this->contains));
        }

        if ([] !== $this->notContains) {
            $parts[] = \sprintf('not containing: %s', implode(', ', $this->notContains));
        }

        if ([] !== $parts) {
            return \sprintf('has %s header with %s', $headerName, implode('; ', $parts));
        }

        return \sprintf('has %s header', $headerName);
    }

    /**
     * @param mixed $other
     */
    protected function matches($other): bool
    {
        if (!$other instanceof Response) {
            return false;
        }

        $headerName = $this->reportOnly ? 'Content-Security-Policy-Report-Only' : 'Content-Security-Policy';

        if (!$other->headers->has($headerName)) {
            return false;
        }

        $cspValue = $other->headers->get($headerName);

        if (null === $cspValue || '' === $cspValue) {
            return false;
        }

        // Check required directives
        if (null !== $this->requiredDirectives) {
            foreach ($this->requiredDirectives as $directive) {
                if (false === strpos($cspValue, $directive)) {
                    return false;
                }
            }
        }

        // Check values that must be present
        foreach ($this->contains as $value) {
            if (false === strpos($cspValue, $value)) {
                return false;
            }
        }

        // Check values that must NOT be present
        foreach ($this->notContains as $value) {
            if (false !== strpos($cspValue, $value)) {
                return false;
            }
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

        $headerName = $this->reportOnly ? 'Content-Security-Policy-Report-Only' : 'Content-Security-Policy';

        if (!$other->headers->has($headerName)) {
            return \sprintf('%s header is missing', $headerName);
        }

        $cspValue = $other->headers->get($headerName);

        if (null === $cspValue || '' === $cspValue) {
            return \sprintf('%s header is empty', $headerName);
        }

        $issues = [];

        // Check missing directives
        if (null !== $this->requiredDirectives) {
            $missingDirectives = [];
            foreach ($this->requiredDirectives as $directive) {
                if (false === strpos($cspValue, $directive)) {
                    $missingDirectives[] = $directive;
                }
            }
            if ([] !== $missingDirectives) {
                $issues[] = \sprintf('missing directives: %s', implode(', ', $missingDirectives));
            }
        }

        // Check missing values
        $missingValues = [];
        foreach ($this->contains as $value) {
            if (false === strpos($cspValue, $value)) {
                $missingValues[] = $value;
            }
        }
        if ([] !== $missingValues) {
            $issues[] = \sprintf('missing values: %s', implode(', ', $missingValues));
        }

        // Check forbidden values that are present
        $forbiddenFound = [];
        foreach ($this->notContains as $value) {
            if (false !== strpos($cspValue, $value)) {
                $forbiddenFound[] = $value;
            }
        }
        if ([] !== $forbiddenFound) {
            $issues[] = \sprintf('forbidden values found: %s', implode(', ', $forbiddenFound));
        }

        if ([] !== $issues) {
            return \sprintf(
                "%s has issues: %s\nActual header: %s",
                $headerName,
                implode('; ', $issues),
                $cspValue
            );
        }

        return \sprintf('%s header validation failed', $headerName);
    }
}
