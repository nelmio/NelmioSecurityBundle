<?php

/*
 * This file is part of the Nelmio SecurityBundle.
 *
 * (c) Nelmio <hello@nelm.io>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Nelmio\SecurityBundle\Controller;

use Psr\Log\LoggerInterface;
use Psr\Log\LogLevel;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use UnexpectedValueException;

class ContentSecurityPolicyController
{
    const TYPE_ENFORCE = 'enforce';
    const TYPE_REPORT = 'report';

    /**
     * @var LoggerInterface
     */
    protected $logger;

    private $logLevels = array(
        LogLevel::EMERGENCY => LogLevel::EMERGENCY,
        LogLevel::ALERT => LogLevel::ALERT,
        LogLevel::CRITICAL => LogLevel::CRITICAL,
        LogLevel::ERROR => LogLevel::ERROR,
        LogLevel::WARNING => LogLevel::WARNING,
        LogLevel::NOTICE => LogLevel::NOTICE,
        LogLevel::INFO => LogLevel::INFO,
        LogLevel::DEBUG => LogLevel::DEBUG,
    );

    /**
     * @param LoggerInterface $logger
     */
    public function __construct(LoggerInterface $logger)
    {
        $this->logger = $logger;
    }

    public function indexAction(Request $request, $type = self::TYPE_ENFORCE, $logLevel = LogLevel::NOTICE)
    {
        $this->validateLogLevel($logLevel);

        $messagePrefix = $this->getMessagePrefix($type);

        $violationReport = $request->getContent();
        if (empty($violationReport)) {
            $this->logger->log($logLevel,
                sprintf('[%s] Content-Security-Policy Endpoint called without data', $messagePrefix)
            );

            return new Response('No report data sent?', 411);
        }

        $violationReport = json_decode($violationReport, true);
        if ($violationReport === null) {
            $this->logger->log($logLevel,
                sprintf('[%s] Content-Security-Policy Endpoint called with invalid JSON data', $messagePrefix)
            );

            return new Response('Invalid JSON data supplied?', 400);
        }

        if (!isset($violationReport['csp-report'])) {
            $this->logger->log($logLevel,
                sprintf('[%s] Content-Security-Policy Endpoint called without "csp-report" data', $messagePrefix)
            );

            return new Response('Invalid report data, no "csp-report" data supplied.', 400);
        }

        $this->logger->log($logLevel,
            sprintf('[%s] Content-Security-Policy Violation Reported', $messagePrefix),
            $violationReport
        );

        return new Response('', 204);
    }

    private function getMessagePrefix($type)
    {
        if (self::TYPE_ENFORCE === $type) {
            return 'Enforce';
        }

        if (self::TYPE_REPORT === $type) {
            return 'Report Only';
        }

        throw new UnexpectedValueException(sprintf('The "type" parameter accepts values: "%s" or "%s", "%s" given.', self::TYPE_ENFORCE, self::TYPE_REPORT, $type));
    }

    private function validateLogLevel($logLevel)
    {
        if (isset($this->logLevels[$logLevel])) {
            return;
        }

        throw new UnexpectedValueException(sprintf('The "logLevel" parameter "%s" is unknown. Use one of log levels defined in class "Psr\Log\LogLevel".', $logLevel));
    }
}
