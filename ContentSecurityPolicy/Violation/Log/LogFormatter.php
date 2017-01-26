<?php

namespace Nelmio\SecurityBundle\ContentSecurityPolicy\Violation\Log;

use Nelmio\SecurityBundle\ContentSecurityPolicy\Violation\Report;

class LogFormatter implements LogFormatterInterface
{
    public function format(Report $report)
    {
        return 'Content-Security-Policy Violation Reported';
    }
}
