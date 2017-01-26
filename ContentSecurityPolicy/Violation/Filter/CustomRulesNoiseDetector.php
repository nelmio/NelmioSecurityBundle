<?php

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

class CustomRulesNoiseDetector implements NoiseDetectorInterface
{
    private $urls;

    public function __construct(array $urls)
    {
        $this->urls = $urls;
    }

    public function match(Report $report, Request $request)
    {
        $uri = $report->getUri();
        $domain = $report->getDomain();

        if (null === $directive = $report->getDirective()) {
            return false;
        }

        foreach ($this->urls as $pattern => $sources) {
            if (!in_array('*', $sources, true) && !in_array($directive, $sources, true)) {
                continue;
            }

            if ($pattern[0] === '/') {
                if (preg_match($pattern, $uri)) {
                    return true;
                }
            } elseif ($pattern === $domain) {
                return true;
            }
        }

        return false;
    }
}
