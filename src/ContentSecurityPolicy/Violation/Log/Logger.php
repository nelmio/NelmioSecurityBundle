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

namespace Nelmio\SecurityBundle\ContentSecurityPolicy\Violation\Log;

use Nelmio\SecurityBundle\ContentSecurityPolicy\Violation\Report;
use Psr\Log\LoggerInterface;

final class Logger
{
    private LoggerInterface $logger;
    private LogFormatterInterface $logFormatter;
    private string $level;

    public function __construct(LoggerInterface $logger, LogFormatterInterface $logFormatter, string $level)
    {
        $this->logger = $logger;
        $this->logFormatter = $logFormatter;
        $this->level = $level;
    }

    public function log(Report $report): void
    {
        $this->logger->log($this->level, $this->logFormatter->format($report), ['csp-report' => $report->getData(), 'user-agent' => $report->getUserAgent()]);
    }

    public function getLogger(): LoggerInterface
    {
        return $this->logger;
    }
}
