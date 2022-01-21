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

namespace Nelmio\SecurityBundle\UserAgent;

interface UserAgentParserInterface
{
    public const BROWSER_CHROME = 'Chrome';
    public const BROWSER_OPERA = 'Opera';
    public const BROWSER_FIREFOX = 'Firefox';
    public const BROWSER_SAFARI = 'Safari';
    public const BROWSER_OTHER = 'Other';

    /**
     * @return string One of the UserAgentParserInterface::BROWSER_* constant
     *
     * @phpstan-return self::BROWSER_*
     */
    public function getBrowser(string $userAgent): string;
}
