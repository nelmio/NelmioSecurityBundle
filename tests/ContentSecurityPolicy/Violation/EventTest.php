<?php

/*
 * This file is part of the Nelmio SecurityBundle.
 *
 * (c) Nelmio <hello@nelm.io>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace ContentSecurityPolicy\Violation;

use Nelmio\SecurityBundle\ContentSecurityPolicy\Violation\Event;
use Nelmio\SecurityBundle\ContentSecurityPolicy\Violation\Report;
use PhpUnit\Framework\TestCase;

class EventTest extends TestCase
{
    public function testCanBeConstructed()
    {
        $this->assertInstanceOf(
            Event::class,
            new Event(new Report([]))
        );
    }
}
