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

final class SchemesNoiseDetector implements NoiseDetectorInterface
{
    public function match(Report $report, Request $request): bool
    {
        static $schemes = [
            'chromeinvoke',
            'chromeinvokeimmediate',
            'gsa', // on mobile safari
            'jar', // firefox extensions
            'mbinit', // map builder
            'mx',
            'ms-appx-web', // MS Edge
            'ms-browser-extension',
            'mxaddon-pkg', // maxthon addon packages
            'mxjscall',
            'none',
            'safari-extension', // safari extensions
            'sinaweibo',
            'sraf',
            'symres', // norton
            'tmtbff', // ticketmaster toolbar
            'webviewprogress',
            'webviewprogressproxy', // added by browsers in webviews
        ];

        if (null === $scheme = $report->getScheme()) {
            return false;
        }

        return \in_array($scheme, $schemes, true);
    }
}
