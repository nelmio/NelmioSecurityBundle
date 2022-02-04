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

namespace Nelmio\SecurityBundle\ContentSecurityPolicy\Violation\Filter;

use Nelmio\SecurityBundle\ContentSecurityPolicy\Violation\Report;
use Symfony\Component\HttpFoundation\Request;

final class CustomRulesNoiseDetector implements NoiseDetectorInterface
{
    /**
     * @var array<string, array<string>>
     */
    private array $urls;

    /**
     * @param array<string, array<string>> $urls
     */
    public function __construct(array $urls)
    {
        $this->urls = $urls;
    }

    public function match(Report $report, Request $request): bool
    {
        $uri = $report->getUri();
        $domain = $report->getDomain();

        if (null === $directive = $report->getDirective()) {
            return false;
        }

        foreach ($this->urls as $pattern => $sources) {
            if (!\in_array('*', $sources, true) && !\in_array($directive, $sources, true)) {
                continue;
            }

            if ('/' === $pattern[0]) {
                if (null !== $uri && 1 === preg_match($pattern, $uri)) {
                    return true;
                }
            } elseif ($pattern === $domain) {
                return true;
            }
        }

        return false;
    }
}
