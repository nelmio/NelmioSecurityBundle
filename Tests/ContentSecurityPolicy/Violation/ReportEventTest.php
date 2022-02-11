<?php

namespace ContentSecurityPolicy\Violation;

use Nelmio\SecurityBundle\ContentSecurityPolicy\Violation\Report;
use Nelmio\SecurityBundle\ContentSecurityPolicy\Violation\ReportEvent;
use PhpUnit\Framework\TestCase;

class ReportEventTest extends TestCase
{
    public function testCanBeConstructed()
    {
        $this->assertInstanceOf(
            ReportEvent::class,
            new ReportEvent(new Report([]))
        );
    }
}
