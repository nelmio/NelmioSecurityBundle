<?php

namespace Nelmio\SecurityBundle\ContentSecurityPolicy\Violation\Log;

use Nelmio\SecurityBundle\ContentSecurityPolicy\Violation\Report;
use Psr\Log\LoggerInterface;

class Logger
{
    private $logger;
    private $logFormatter;
    private $level;

    public function __construct(LoggerInterface $logger, LogFormatterInterface $logFormatter, $level)
    {
        $this->logger = $logger;
        $this->logFormatter = $logFormatter;
        $this->level = $level;
    }

    public function log(Report $report)
    {
        $this->logger->log($this->level, $this->logFormatter->format($report), array('csp-report' => $report->getData(), 'user-agent' => $report->getUserAgent()));
    }

    public function getLogger()
    {
        return $this->logger;
    }
}
