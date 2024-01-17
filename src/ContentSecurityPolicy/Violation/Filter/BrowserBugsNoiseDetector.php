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
use UAParser\Parser;

final class BrowserBugsNoiseDetector implements NoiseDetectorInterface
{
    private Parser $uaParser;

    public function __construct(Parser $uaParser)
    {
        $this->uaParser = $uaParser;
    }

    public function match(Report $report, Request $request): bool
    {
        // https://bugzilla.mozilla.org/show_bug.cgi?id=1026520
        if ('script-src' === $report->getDirective() && 'self' === $report->getUri()) {
            if (null !== $ua = $request->headers->get('user-agent')) {
                $result = $this->uaParser->parse($ua);

                if ('Firefox' === $result->ua->family && $result->ua->major < 43) {
                    return true;
                }
            }
        }

        // https://bugzilla.mozilla.org/show_bug.cgi?id=1445643
        if ('moz-extension' === $report->getUri()) {
            return true;
        }

        // https://bugzilla.mozilla.org/show_bug.cgi?id=1263286
        if ('base-uri' === $report->getDirective() && \in_array($report->getUri(), ['about:blank', 'about'], true)) {
            if (null !== $ua = $request->headers->get('user-agent')) {
                $result = $this->uaParser->parse($ua);

                if (\in_array($result->ua->family, ['Firefox', 'Iceweasel', 'Firefox Mobile'], true) && $result->ua->major < 49) {
                    return true;
                }
            }
        }

        // https://bugzilla.mozilla.org/show_bug.cgi?id=1873553
        if ('view-source' === $report->getSourceFile()) {
            return true;
        }

        // files loaded by safari & firefox extension
        // should be allowed as in Chrome
        if (
            ($sourceFile = $report->getSourceFile()) !== null
            && (0 === strpos($sourceFile, 'safari-extension://') || 'moz-extension' === $sourceFile)
        ) {
            return true;
        }

        return false;
    }
}
