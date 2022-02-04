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

final class InjectedScriptsNoiseDetector implements NoiseDetectorInterface
{
    public function match(Report $report, Request $request): bool
    {
        $patterns = [
            '/installGlobalHook\(window\)/',
            '/var lastpass_it/',
            '/Object\.defineProperty/',
            '/var event_id/',
            '/window\.oldSetTimeout=window\.setTimeout/',
            '/_PostRPC\(\)/',
            '/window\.devToolsOptions/',
            '/AG_onLoad\s*=/',
            '/var FuckAdBlo/',
            '/var BlockAdBlo/',
            '/attribute on DIV element/',
            '/safeWindow:\{\}/',
            '/ abNoOp/',
            '/var fake/',
            '/\.Wondersh/',
            '/videodownload2/',
            '/jq_relocation/',
            '/jQuery JavaScript/',
            '/jquery\.base64\.js/',
        ];

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
            if (1 === preg_match($pattern, $sample)) {
                return true;
            }
        }

        return false;
    }
}
