<?php

/*
 * This file is part of the Nelmio SecurityBundle.
 *
 * (c) Nelmio <hello@nelm.io>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Nelmio\SecurityBundle\UserAgent;

use UAParser\Parser;

class UAParserUserAgentParser implements UserAgentParserInterface
{
    private $parser;

    public function __construct(Parser $parser)
    {
        $this->parser = $parser;
    }

    /**
     * {@inheritdoc}
     */
    public function getBrowser($userAgent)
    {
        $name = strtolower($this->parser->parse($userAgent)->ua->family);

        switch (true) {
            case 'chrome' === $name:
                return self::BROWSER_CHROME;
            case 'firefox' === $name:
                return self::BROWSER_FIREFOX;
            case 'opera' === $name:
                return self::BROWSER_OPERA;
            case 'safari' === $name:
            case 'mobile safari' === $name:
                return self::BROWSER_SAFARI;

            case 'chrome ' === substr($name, 0, 7):
                return self::BROWSER_CHROME;

            case 'firefox ' === substr($name, 0, 8):
                return self::BROWSER_FIREFOX;

            case 'opera ' === substr($name, 0, 6):
                return self::BROWSER_OPERA;

            default:
                return self::BROWSER_OTHER;
        }
    }
}
