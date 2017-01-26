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

class SchemesNoiseDetector implements NoiseDetectorInterface
{
    public function match(Report $report, Request $request)
    {
        static $schemes = array(
            'safari-extension', // safari extensions
            'jar', // firefox extensions
            'mxaddon-pkg', // maxthon addon packages
            'tmtbff', // ticketmaster toolbar
            'symres', // norton
            'mbinit', // map builder
            'webviewprogressproxy', // added by browsers in webviews
            'mx',
            'gsa', // on mobile safari
            'chromeinvoke',
            'chromeinvokeimmediate',
            'webviewprogress',
            'mxjscall',
            'ms-appx-web', // MS Edge
            'sinaweibo',
            'none',
        );

        if (null === $scheme = $report->getScheme()) {
            return false;
        }

        return in_array($scheme, $schemes, true);
    }
}
