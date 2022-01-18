<?php

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
