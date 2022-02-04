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

final class DomainsRegexNoiseDetector implements NoiseDetectorInterface
{
    public function match(Report $report, Request $request): bool
    {
        static $patterns = [
            '/^https?:\/\/.*\.pinterest\.com/',
            '/^https?:\/\/.*\.prestadb\.net/',
            '/^https?:\/\/.+\.akamaihd\.net/',
            '/^https?:\/\/.+\.cmptch\.com/',
            '/^https?:\/\/.+\.dnsqa\.me/',
            '/^https?:\/\/.+\.grammarly\.io/',
            '/^https?:\/\/.+\.hwcdn\.net/',
            '/^https?:\/\/.+\.tlscdn\.com/',
            '/^https?:\/\/.+\.visadd\.com/',
            '/^https?:\/\/.*.youdao\.com/',
            '/^https?:\/\/\*\.capgemini\.com/',
            '/^https?:\/\/.*.dnsqa2016.com/',
            '/^https?:\/\/.*.jollywallet.com/',
            '/^https?:\/\/.*\.dnsqa365\./',
            '/^https?:\/\/.*\.dnsqa\./',
            '/^https?:\/\/\d+\.media\.tumblr\.com/',
            '/^https?:\/\/www\.alldebrid\.fr/',
            '/^https?:\/\/.*\.blogspot\.com/',
            '/^https?:\/\/bit\.ly/',
            '/^https?:\/\/browser\.gwdang\.com/',
        ];

        if (null === $uri = $report->getUri()) {
            return false;
        }

        foreach ($patterns as $pattern) {
            if (1 === preg_match($pattern, $uri)) {
                return true;
            }
        }

        return false;
    }
}
