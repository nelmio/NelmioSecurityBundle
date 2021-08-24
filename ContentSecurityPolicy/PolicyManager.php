<?php

/*
 * This file is part of the Nelmio SecurityBundle.
 *
 * (c) Nelmio <hello@nelm.io>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Nelmio\SecurityBundle\ContentSecurityPolicy;

use Nelmio\SecurityBundle\UserAgent\UserAgentParserInterface;
use Symfony\Component\HttpFoundation\Request;

class PolicyManager
{
    private $uaParser;

    public function __construct(UserAgentParserInterface $uaParser = null)
    {
        $this->uaParser = $uaParser;
    }

    /**
     * Returns the list of supported directives for the current Request
     *
     * @param Request $request
     *
     * @return array
     */
    public function getAvailableDirective(Request $request)
    {
        if (null === $this->uaParser) {
            return $this->getChromeDirectives();
        }

        switch ($this->uaParser->getBrowser($request->headers->get('user-agent'))) {
            case UserAgentParserInterface::BROWSER_CHROME:
            case UserAgentParserInterface::BROWSER_OPERA:
            case UserAgentParserInterface::BROWSER_OTHER:
                return $this->getChromeDirectives();
            case UserAgentParserInterface::BROWSER_FIREFOX:
                return $this->getFirefoxDirectives();
            case UserAgentParserInterface::BROWSER_SAFARI:
                return $this->getLevel1();
        }
    }

    private function getChromeDirectives()
    {
        return array_merge($this->getLevel3(), $this->getDraftDirectives());
    }

    private function getFirefoxDirectives()
    {
        return array_diff(array_merge($this->getLevel3(), $this->getDraftDirectives()), array(
            'block-all-mixed-content',
            'child-src',
            'plugin-types',
        ));
    }

    private function getLevel1()
    {
        static $directives = array(
            'default-src',
            'connect-src',
            'font-src',
            'frame-src',
            'img-src',
            'media-src',
            'object-src',
            'sandbox',
            'script-src',
            'style-src',
            'report-uri',
        );

        return $directives;
    }

    private function getLevel2()
    {
        static $directives = null;

        if (null === $directives) {
            $directives = array_merge($this->getLevel1(), array(
                'base-uri',
                'child-src',
                'form-action',
                'frame-ancestors',
                'plugin-types',
            ));
        }

        return $directives;
    }

    private function getLevel3()
    {
        static $directives = null;

        if (null === $directives) {
            $directives = array_merge($this->getLevel2(), array(
                'manifest-src',
                'reflected-xss',
                'worker-src',
                'prefetch-src',
            ));
        }

        return $directives;
    }

    private function getDraftDirectives()
    {
        static $directives = array(
            'block-all-mixed-content',
            'upgrade-insecure-requests',
        );

        return $directives;
    }
}
