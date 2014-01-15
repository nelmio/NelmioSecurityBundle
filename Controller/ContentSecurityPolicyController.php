<?php

namespace Nelmio\SecurityBundle\Controller;

use Psr\Log\LoggerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\Controller;
use Symfony\Bundle\MonologBundle\MonologBundle;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class ContentSecurityPolicyController extends Controller
{
    /**
     * @Route("/csp/report", name="_nelmio_csp_reporting")
     */
    public function indexAction(Request $request)
    {
        $logger = $this->getLogger();
        if (!$logger) {
            return new Response('Thanks but I cant process this right now', 501);
        }

        $violationReport = $request->getContent();
        if (empty($violationReport)) {
            $logger->notice('Content-Security-Policy Endpoint called without data?');
            return new Response('No report data sent?', 411);
        }

        $violationReport = json_decode($violationReport, true);
        if ($violationReport === NULL) {
            $logger->notice('Content-Security-Policy Endpoint called with invalid JSON data?');
            return new Response('Invalid JSON data supplied?', 400);
        }

        if (!isset($violationReport['csp-report'])) {
            $logger->notice('Content-Security-Policy Endpoint called without "csp-report" data?');
            return new Response('Invalid report data, no "csp-report" data supplied.', 400);
        }

        $logger->notice(
            'Content-Security-Policy Violation Reported',
            $violationReport
        );
        return new Response('Thanks! This has been reported to the administrator.', 200);
    }

    /**
     * Get a PSR compatible logger for logging CSP violations.
     *
     * Trying in order:
     * * nelmio_security.csp_report_logger
     * * security.logger
     * * logger
     *
     * @return bool|LoggerInterface
     */
    protected function getLogger()
    {
        $loggerIds = array('nelmio_security.csp_report_logger', 'security.logger', 'logger');

        foreach ($loggerIds as $loggerId) {
            if (!$this->container->has($loggerId)) {
                continue;
            }

            $logger = $this->get($loggerId);
            if (!$logger instanceof LoggerInterface) {
                continue;
            }

            return $logger;
        }
        return false;
    }
}
