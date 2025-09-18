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

namespace Nelmio\SecurityBundle\Tests\PermissionsPolicy;

use Nelmio\SecurityBundle\PermissionsPolicy\Exception\UnsupportedDirectiveException;
use Nelmio\SecurityBundle\PermissionsPolicy\Mapping;
use Nelmio\SecurityBundle\Tests\Listener\ListenerTestCase;

final class MappingTest extends ListenerTestCase
{
    public function testAll(): void
    {
        $this->assertSame([
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
        ], Mapping::all());
    }

    /**
     * @dataProvider directives
     *
     * @param array<Mapping::VALUE_*> $expected
     */
    public function testGet(array $expected, string $directive): void
    {
        $this->assertSame($expected, Mapping::get($directive));
    }

    /**
     * @return iterable<string, array{0: array<Mapping::VALUE_*>, 1: string}>
     */
    public static function directives(): iterable
    {
        foreach (Mapping::all() as $directive => $values) {
            yield $directive => [$values, $directive];
        }
    }

    /**
     * @dataProvider directiveInvalid
     */
    public function testGetInvalid(string $directive): void
    {
        $this->expectException(UnsupportedDirectiveException::class);

        Mapping::get($directive);
    }

    /**
     * @return iterable<string, string[]>
     */
    public static function directiveInvalid(): iterable
    {
        yield 'invalid-directive' => ['invalid-directive'];
        yield 'whitespace only' => [' '];
        yield 'empty string' => [''];
    }
}
