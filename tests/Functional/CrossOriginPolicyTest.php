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

final class CrossOriginPolicyTest extends WebTestCase
{
    public function testHasHeaders(): void
    {
        $client = static::createClient();

        $client->request('GET', '/');

        $this->assertResponseHeaderSame('cross-origin-embedder-policy', 'credentialless');
        $this->assertResponseHeaderSame('cross-origin-opener-policy', 'same-origin');
        $this->assertResponseHeaderSame('cross-origin-resource-policy', 'cross-origin');
    }
}
