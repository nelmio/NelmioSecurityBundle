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

namespace Nelmio\SecurityBundle\EventListener;

use Nelmio\SecurityBundle\SignedCookie\LegacySignatureCookieTrackerInterface;
use Nelmio\SecurityBundle\SignedCookie\UpgradedCookieBuilderInterface;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\ResponseEvent;

class SignedCookieUpgradeListener
{
    private LegacySignatureCookieTrackerInterface $legacySignatureCookieTracker;

    private UpgradedCookieBuilderInterface $upgradedCookieBuilder;

    public function __construct(LegacySignatureCookieTrackerInterface $legacySignatureCookieTracker, UpgradedCookieBuilderInterface $upgradedCookieBuilder)
    {
        $this->legacySignatureCookieTracker = $legacySignatureCookieTracker;
        $this->upgradedCookieBuilder = $upgradedCookieBuilder;
    }

    public function onKernelResponse(ResponseEvent $event): void
    {
        if (!$event->isMainRequest()) {
            return;
        }

        $response = $event->getResponse();
        $request = $event->getRequest();

        $currentResponseCookies = $this->extractCookieNames($response);
        foreach ($this->legacySignatureCookieTracker->getCookiesForUpgrade() as $name) {
            if (\in_array($name, $currentResponseCookies, true)) {
                continue;
            }
            $cookie = $this->upgradedCookieBuilder->build($name, $request->cookies->get($name));
            if (null === $cookie) {
                continue;
            }

            $response->headers->setCookie($cookie);
        }
    }

    /**
     * @return string[]
     */
    private function extractCookieNames(Response $response): array
    {
        $names = [];
        $cookies = $response->headers->getCookies();
        foreach ($cookies as $cookie) {
            $names[] = $cookie->getName();
        }

        return $names;
    }
}
