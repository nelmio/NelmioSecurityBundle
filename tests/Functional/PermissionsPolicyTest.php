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

        $this->assertResponseHeaderSame('permissions-policy', 'camera=(), microphone=(self), geolocation=(*), fullscreen=(self "https://trusted-domain.com"), interest-cohort=(), payment=(), accelerometer=(), gyroscope=(), magnetometer=(), usb=(), autoplay=(), encrypted-media=(), picture-in-picture=(), display-capture=(), web-share=(), clipboard-read=(), clipboard-write=(), gamepad=(), speaker-selection=(), conversion-measurement=(), focus-without-user-activation=(), hid=(), idle-detection=(), local-fonts=(), midi=(), otp-credentials=(), publickey-credentials-get=(), screen-wake-lock=(), serial=(), storage-access=(), window-placement=(), xr-spatial-tracking=()');
    }
}
