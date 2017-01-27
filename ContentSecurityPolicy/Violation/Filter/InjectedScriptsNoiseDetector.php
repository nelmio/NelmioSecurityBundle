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

class InjectedScriptsNoiseDetector implements NoiseDetectorInterface
{
    public function match(Report $report, Request $request)
    {
        $patterns = array(
            '/^\s*;\(function installGlobalHook\(window\) \{/',
            '/^try\s+\{\s+for\(var lastpass_iter=0; lastpass/',
            '/^try\{\(function\(\) \{ for\(var lastpass_it/',
            '/^\(function \(\)\{try\{Object\.defineProperty/',
            '/^\(function \(\) \{\s+var event_id = docum/',
            '/^\s*window\.oldSetTimeout=window\.setTimeout/',
            '/^try \{\s*window.AG_onLoad = function\(/',
            '/var FuckAdBlock/',
            '/var BlockAdBlock/',
        );

        if ('self' !== $report->getUri()) {
            return false;
        }

        if ('script-src' !== $report->getDirective()) {
            return false;
        }

        if (null === $sample = $report->getScriptSample()) {
            return false;
        }

        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $sample)) {
                return true;
            }
        }

        return false;
    }
}
