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

namespace Nelmio\SecurityBundle\ContentSecurityPolicy;

use Nelmio\SecurityBundle\UserAgent\UserAgentParserInterface;
use Symfony\Component\HttpFoundation\Request;

final class PolicyManager
{
    private ?UserAgentParserInterface $uaParser;

    public function __construct(?UserAgentParserInterface $uaParser = null)
    {
        $this->uaParser = $uaParser;
    }

    /**
     * Returns the list of supported directives for the current Request.
     *
     * @return list<string>
     */
    public function getAvailableDirective(Request $request): array
    {
        if (null === $this->uaParser) {
            return $this->getChromeDirectives();
        }

        $userAgent = $request->headers->get('user-agent');

        if (null === $userAgent) {
            return [];
        }

        switch ($this->uaParser->getBrowser($userAgent)) {
            case UserAgentParserInterface::BROWSER_CHROME:
            case UserAgentParserInterface::BROWSER_OPERA:
            case UserAgentParserInterface::BROWSER_OTHER:
                return $this->getChromeDirectives();
            case UserAgentParserInterface::BROWSER_FIREFOX:
                return $this->getFirefoxDirectives();
            case UserAgentParserInterface::BROWSER_SAFARI:
                return $this->getLevel1();
            default:
                return [];
        }
    }

    /**
     * @return list<string>
     */
    private function getChromeDirectives(): array
    {
        return [...$this->getLevel3(), ...$this->getDraftDirectives()];
    }

    /**
     * @return list<string>
     */
    private function getFirefoxDirectives(): array
    {
        return array_diff([...$this->getLevel3(), ...$this->getDraftDirectives()], [
            'block-all-mixed-content',
            'child-src',
            'plugin-types',
        ]);
    }

    /**
     * @return list<string>
     */
    private function getLevel1(): array
    {
        static $directives = [
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
        ];

        return $directives;
    }

    /**
     * @return list<string>
     */
    private function getLevel2(): array
    {
        static $directives = null;

        if (null === $directives) {
            $directives = array_merge($this->getLevel1(), [
                'base-uri',
                'child-src',
                'form-action',
                'frame-ancestors',
                'plugin-types',
            ]);
        }

        return $directives;
    }

    /**
     * @return list<string>
     */
    private function getLevel3(): array
    {
        static $directives = null;

        if (null === $directives) {
            $directives = array_merge($this->getLevel2(), [
                'manifest-src',
                'reflected-xss',
                'worker-src',
                'prefetch-src',
                'report-to',
            ]);
        }

        return $directives;
    }

    /**
     * @return list<string>
     */
    private function getDraftDirectives(): array
    {
        static $directives = [
            'block-all-mixed-content',
            'upgrade-insecure-requests',
        ];

        return $directives;
    }
}
