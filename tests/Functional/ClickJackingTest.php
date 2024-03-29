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

final class ClickJackingTest extends WebTestCase
{
    public function testDoesNotHasHeader(): void
    {
        $client = static::createClient();

        $client->request('GET', '/clickjacking/allow');

        $this->assertResponseIsSuccessful();
        $this->assertResponseNotHasHeader('x-frame-options');
    }

    public function testDenyHeaders(): void
    {
        $client = static::createClient();

        $client->request('GET', '/clickjacking/deny');

        $this->assertResponseIsSuccessful();
        self::assertResponseHeaderSame('x-frame-options', 'DENY');
    }
}
