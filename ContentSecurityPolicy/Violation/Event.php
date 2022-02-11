<?php

/*
 * This file is part of the Nelmio SecurityBundle.
 *
 * (c) Nelmio <hello@nelm.io>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Nelmio\SecurityBundle\ContentSecurityPolicy\Violation;

if (\class_exists(\Symfony\Component\EventDispatcher\Event::class)) {
    /**
     * @internal
     */
    class BaseEvent extends \Symfony\Component\EventDispatcher\Event
    {
    }
} else {
    /**
     * @internal
     */
    class BaseEvent extends \Symfony\Contracts\EventDispatcher\Event
    {
    }
}

/**
 * @deprecated since nelmio/security-bundle 2.12, use ReportEvent instead.
 */
class Event extends BaseEvent
{
    private $report;

    public function __construct(Report $report)
    {
        $this->report = $report;
    }

    public function getReport()
    {
        return $this->report;
    }
}
