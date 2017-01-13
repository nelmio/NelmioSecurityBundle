<?php

namespace Nelmio\SecurityBundle\ContentSecurityPolicy\Violation\Log;

use Nelmio\SecurityBundle\ContentSecurityPolicy\Violation\Report;

interface LogFormatterInterface
{
    /**
     * Returns a log message given a report
     *
     * @return string
     */
    public function format(Report $report);
}
