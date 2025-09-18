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

namespace Nelmio\SecurityBundle\Tests\Functional;

use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

final class PermissionsPolicyTest extends WebTestCase
{
    public function testHasHeaders(): void
    {
        $client = static::createClient();

        $client->request('GET', '/');

        $this->assertResponseHeaderSame('permissions-policy', 'camera=(), microphone=(self), geolocation=(*), fullscreen=(self "https://trusted-domain.com"), interest-cohort=(), accelerometer=(self), ambient-light-sensor=(self), attribution-reporting=(*), autoplay=(self), bluetooth=(self), browsing-topics=(*), captured-surface-control=(self), compute-pressure=(self), cross-origin-isolated=(self), deferred-fetch=(self), deferred-fetch-minimal=(*), display-capture=(self), encrypted-media=(self), gamepad=(self), gyroscope=(self), hid=(self), identity-credentials-get=(self), idle-detection=(self), language-detector=(self), local-fonts=(self), magnetometer=(self), midi=(self), otp-credentials=(self), payment=(self), picture-in-picture=(*), publickey-credentials-create=(self), publickey-credentials-get=(self), screen-wake-lock=(self), serial=(self), speaker-selection=(self), storage-access=(*), summarizer=(self), translator=(self), usb=(self), web-share=(self), window-management=(self), xr-spatial-tracking=(self)');
    }
}
