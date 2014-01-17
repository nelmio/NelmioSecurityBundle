<?php

namespace Nelmio\SecurityBundle\Controller;

use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

class ContentSecurityPolicyController
{
    /**
     * @var LoggerInterface
     */
    protected $logger;

    /**
     * @param LoggerInterface $logger
     */
    public function __construct(LoggerInterface $logger)
    {
        $this->logger = $logger;
    }

    public function indexAction(Request $request)
    {
        $violationReport = $request->getContent();
        if (empty($violationReport)) {
            $this->logger->notice('Content-Security-Policy Endpoint called without data');

            return new Response('No report data sent?', 411);
        }

        $violationReport = json_decode($violationReport, true);
        if ($violationReport === null) {
            $this->logger->notice('Content-Security-Policy Endpoint called with invalid JSON data');

            return new Response('Invalid JSON data supplied?', 400);
        }

        if (!isset($violationReport['csp-report'])) {
            $this->logger->notice('Content-Security-Policy Endpoint called without "csp-report" data');

            return new Response('Invalid report data, no "csp-report" data supplied.', 400);
        }

        $this->logger->notice(
            'Content-Security-Policy Violation Reported',
            $violationReport
        );

        return new Response('', 204);
    }
}
