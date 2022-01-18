<?php

/*
 * This file is part of the Nelmio SecurityBundle.
 *
 * (c) Nelmio <hello@nelm.io>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace  Nelmio\SecurityBundle\UserAgent;

interface UserAgentParserInterface
{
    const BROWSER_CHROME = 'Chrome';
    const BROWSER_OPERA = 'Opera';
    const BROWSER_FIREFOX = 'Firefox';
    const BROWSER_SAFARI = 'Safari';
    const BROWSER_OTHER = 'Other';

    /**
     * @param $userAgent string The user agent to parse
     *
     * @return string One of the UserAgentParserInterface::BROWSER_* constant
     */
    public function getBrowser($userAgent);
}
