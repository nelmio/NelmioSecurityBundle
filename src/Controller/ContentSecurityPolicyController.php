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

namespace Nelmio\SecurityBundle\Controller;

use Nelmio\SecurityBundle\ContentSecurityPolicy\Violation\Exception\ExceptionInterface;
use Nelmio\SecurityBundle\ContentSecurityPolicy\Violation\Filter\Filter;
use Nelmio\SecurityBundle\ContentSecurityPolicy\Violation\Log\Logger;
use Nelmio\SecurityBundle\ContentSecurityPolicy\Violation\Report;
use Nelmio\SecurityBundle\ContentSecurityPolicy\Violation\ReportEvent;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Contracts\EventDispatcher\EventDispatcherInterface;

final class ContentSecurityPolicyController
{
    private Logger $logger;
    private Filter $filter;
    private EventDispatcherInterface $dispatcher;

    public function __construct(Logger $logger, EventDispatcherInterface $dispatcher, Filter $filter)
    {
        $this->logger = $logger;
        $this->filter = $filter;
        $this->dispatcher = $dispatcher;
    }

    public function indexAction(Request $request): Response
    {
        try {
            $report = Report::fromRequest($request);
        } catch (ExceptionInterface $e) {
            $this->logger->getLogger()->notice($e->getMessage());

            return new Response($e->getMessage(), $e->getCode());
        }

        if ($this->filter->filter($request, $report)) {
            return new Response('', 204);
        }

        $this->dispatcher->dispatch(new ReportEvent($report));

        $this->logger->log($report);

        return new Response('', 204);
    }
}
