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

namespace Nelmio\SecurityBundle\Tests\SignedCookie;

use Nelmio\SecurityBundle\SignedCookie\LegacySignatureCookieTracker;
use PHPUnit\Framework\TestCase;

class LegacySignatureCookieTrackerTest extends TestCase
{
    public function testCollectsCookieNames(): void
    {
        $tracker = new LegacySignatureCookieTracker();
        $tracker->flagForUpgrade('legacy_cookie');
        $tracker->flagForUpgrade('another_legacy_cookie');
        $tracker->flagForUpgrade('legacy_cookie');

        $this->assertSame(['legacy_cookie', 'another_legacy_cookie'], $tracker->getCookiesForUpgrade());
    }

    public function testClearsCookieNames(): void
    {
        $tracker = new LegacySignatureCookieTracker();
        $tracker->flagForUpgrade('legacy_cookie');

        $this->assertSame(['legacy_cookie'], $tracker->getCookiesForUpgrade());

        $tracker->clear();

        $this->assertEmpty($tracker->getCookiesForUpgrade());
    }
}
