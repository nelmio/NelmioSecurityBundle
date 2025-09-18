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

namespace Nelmio\SecurityBundle\PermissionsPolicy;

use Nelmio\SecurityBundle\PermissionsPolicy\Exception\UnsupportedDirectiveException;

/**
 * @internal
 *
 * @author Silas Joisten <silasjoisten@proton.me>
 */
final class Mapping
{
    public const VALUE_ALL = '*';
    public const VALUE_SELF = 'self';
    public const VALUE_SRC = 'src';

    /**
     * @var self::VALUE_*[]
     *
     * @see https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Permissions-Policy
     */
    public const ALLOWED_VALUES = [
        self::VALUE_ALL,
        self::VALUE_SELF,
        self::VALUE_SRC,
    ];

    private function __construct()
    {
    }

    /**
     * @return array<string, self::VALUE_*[]>
     *
     * @see https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Permissions-Policy#directives
     */
    public static function all(): array
    {
        return [
            'accelerometer' => ['self'],
            'ambient-light-sensor' => ['self'],
            'attribution-reporting' => ['*'],
            'autoplay' => ['self'],
            'bluetooth' => ['self'],
            'browsing-topics' => ['*'],
            'camera' => ['self'],
            'captured-surface-control' => ['self'],
            'compute-pressure' => ['self'],
            'cross-origin-isolated' => ['self'],
            'deferred-fetch' => ['self'],
            'deferred-fetch-minimal' => ['*'],
            'display-capture' => ['self'],
            'encrypted-media' => ['self'],
            'fullscreen' => ['self'],
            'gamepad' => ['self'],
            'geolocation' => ['self'],
            'gyroscope' => ['self'],
            'hid' => ['self'],
            'identity-credentials-get' => ['self'],
            'idle-detection' => ['self'],
            'interest-cohort' => [],
            'language-detector' => ['self'],
            'local-fonts' => ['self'],
            'magnetometer' => ['self'],
            'microphone' => ['self'],
            'midi' => ['self'],
            'otp-credentials' => ['self'],
            'payment' => ['self'],
            'picture-in-picture' => ['*'],
            'publickey-credentials-create' => ['self'],
            'publickey-credentials-get' => ['self'],
            'screen-wake-lock' => ['self'],
            'serial' => ['self'],
            'speaker-selection' => ['self'],
            'storage-access' => ['*'],
            'summarizer' => ['self'],
            'translator' => ['self'],
            'usb' => ['self'],
            'web-share' => ['self'],
            'window-management' => ['self'],
            'xr-spatial-tracking' => ['self'],
        ];
    }

    /**
     * @return array<self::VALUE_*>
     */
    public static function get(string $directive): array
    {
        if (!\array_key_exists($directive, self::all())) {
            throw new UnsupportedDirectiveException(\sprintf('The directive "%s" is not supported.', $directive));
        }

        return self::all()[$directive];
    }
}
