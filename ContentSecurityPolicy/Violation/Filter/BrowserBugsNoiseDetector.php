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
use UAParser\Parser;

class BrowserBugsNoiseDetector implements NoiseDetectorInterface
{
    private $uaParser;

    public function __construct(Parser $uaParser)
    {
        $this->uaParser = $uaParser;
    }

    public function match(Report $report, Request $request)
    {
        // https://bugzilla.mozilla.org/show_bug.cgi?id=1026520
        if ($report->getDirective() === 'script-src' && $report->getUri() === 'self') {
            if (null !== $ua = $request->headers->get('user-agent')) {
                $result = $this->uaParser->parse($ua);

                if ($result->ua->family === 'Firefox' && $result->ua->major < 43) {
                    return true;
                }
            }
        }
        
        // https://bugzilla.mozilla.org/show_bug.cgi?id=1445643
        if ($report->getUri() === 'moz-extension') {
            return true;
        }

        // https://bugzilla.mozilla.org/show_bug.cgi?id=1263286
        if ($report->getDirective() === 'base-uri' && in_array($report->getUri(), array('about:blank', 'about'), true)) {
            if (null !== $ua = $request->headers->get('user-agent')) {
                $result = $this->uaParser->parse($ua);

                if (in_array($result->ua->family, array('Firefox', 'Iceweasel', 'Firefox Mobile'), true) && $result->ua->major < 49) {
                    return true;
                }
            }
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
