<?php

/*
 * This file is part of the Nelmio SecurityBundle.
 *
 * (c) Nelmio <hello@nelm.io>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

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
        $this->logger->log($this->level, $this->logFormatter->format($report), ['csp-report' => $report->getData()]);
    }

    public function getLogger()
    {
        return $this->logger;
    }
}
