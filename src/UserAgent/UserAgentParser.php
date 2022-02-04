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

use Nelmio\SecurityBundle\UserAgent\UAFamilyParser\UAFamilyParserInterface;

final class UserAgentParser implements UserAgentParserInterface
{
    private UAFamilyParserInterface $parser;

    public function __construct(UAFamilyParserInterface $parser)
    {
        $this->parser = $parser;
    }

    public function getBrowser(string $userAgent): string
    {
        $name = $this->parser->getUaFamily($userAgent);

        switch (true) {
            case 'chrome ' === substr($name, 0, 7):
            case 'chrome' === $name:
                return self::BROWSER_CHROME;
            case 'firefox ' === substr($name, 0, 8):
            case 'firefox' === $name:
                return self::BROWSER_FIREFOX;
            case 'opera ' === substr($name, 0, 6):
            case 'opera' === $name:
                return self::BROWSER_OPERA;
            case 'safari' === $name:
            case 'mobile safari' === $name:
                return self::BROWSER_SAFARI;

            default:
                return self::BROWSER_OTHER;
        }
    }
}
