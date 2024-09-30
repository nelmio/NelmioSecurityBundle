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

namespace Nelmio\SecurityBundle\SignedCookie;

class LegacySignatureCookieTracker implements LegacySignatureCookieTrackerInterface
{
    /**
     * @var string[]
     */
    private array $names = [];

    public function flagForUpgrade(string $cookieName): void
    {
        if (\in_array($cookieName, $this->names, true)) {
            return;
        }
        $this->names[] = $cookieName;
    }

    public function getCookiesForUpgrade(): array
    {
        return $this->names;
    }

    public function clear(): void
    {
        $this->names = [];
    }
}
