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

use Nelmio\SecurityBundle\ContentSecurityPolicy\Violation\Event;
use Nelmio\SecurityBundle\ContentSecurityPolicy\Violation\Events;
use Nelmio\SecurityBundle\ContentSecurityPolicy\Violation\Exception\ExceptionInterface;
use Nelmio\SecurityBundle\ContentSecurityPolicy\Violation\Filter\Filter;
use Nelmio\SecurityBundle\ContentSecurityPolicy\Violation\Log\Logger;
use Nelmio\SecurityBundle\ContentSecurityPolicy\Violation\Report;
use Psr\Log\LoggerInterface;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

class ContentSecurityPolicyController
{
    protected $logger;
    private $filter;
    private $dispatcher;

    public function __construct($logger, EventDispatcherInterface $dispatcher = null, Filter $filter = null)
    {
        $this->logger = $logger;
        $this->filter = $filter;
        $this->dispatcher = $dispatcher;

        if ($logger instanceof LoggerInterface) {
            trigger_error(sprintf('Using a Psr\Log\LoggerInterface as first argument has been deprecated in version 2.1'.
                ' and will not be supported anymore in version 3; use a %s instance instead.', self::class, Logger::class), E_USER_DEPRECATED);
        }
        if (null === $dispatcher) {
            trigger_error(sprintf('%s\'s takes an %s instance as second argument since version 2.1; it will be required in version 3', self::class, EventDispatcherInterface::class), E_USER_DEPRECATED);
        }
        if (null === $filter) {
            trigger_error(sprintf('%s\'s takes an %s instance as third argument since version 2.1; it will be required in version 3', self::class, Filter::class), E_USER_DEPRECATED);
        }
    }

    public function indexAction(Request $request)
    {
        try {
            $report = Report::fromRequest($request);
        } catch (ExceptionInterface $e) {
            if ($this->logger instanceof LoggerInterface) {
                // deprecated
                $this->logger->notice($e->getMessage());
            } else {
                $this->logger->getLogger()->notice($e->getMessage());
            }

            return new Response($e->getMessage(), $e->getCode());
        }

        if ($this->filter && $this->filter->filter($request, $report)) {
            return new Response('', 204);
        }

        if ($this->dispatcher) {
            $this->dispatcher->dispatch(Events::VIOLATION_REPORT, new Event($report));
        }

        if ($this->logger instanceof LoggerInterface) {
            // deprecated
            $this->logger->notice('Content-Security-Policy Violation Reported', array('csp-report' => $report->getData()));
        } else {
            $this->logger->log($report);
        }

        return new Response('', 204);
    }
}
