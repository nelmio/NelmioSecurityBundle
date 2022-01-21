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

namespace Nelmio\SecurityBundle\Tests\ContentSecurityPolicy\Violation;

use Nelmio\SecurityBundle\ContentSecurityPolicy\Violation\Exception\InvalidPayloadException;
use Nelmio\SecurityBundle\ContentSecurityPolicy\Violation\Exception\MissingCspReportException;
use Nelmio\SecurityBundle\ContentSecurityPolicy\Violation\Exception\NoDataException;
use Nelmio\SecurityBundle\ContentSecurityPolicy\Violation\Report;
use Symfony\Component\HttpFoundation\Request;

class ReportTest extends \PHPUnit\Framework\TestCase
{
    public function testFromRequestWithoutData()
    {
        $this->expectException(NoDataException::class);
        $this->expectExceptionMessage('Content-Security-Policy Endpoint called without data');

        Report::fromRequest(new Request());
    }

    public function testFromRequestWithoutReportKey()
    {
        $this->expectException(MissingCspReportException::class);
        $this->expectExceptionMessage('Content-Security-Policy Endpoint called without "csp-report" data');

        Report::fromRequest(new Request([], [], [], [], [], [], '{}'));
    }

    public function testFromRequestWithInvalidJSON()
    {
        $this->expectException(InvalidPayloadException::class);
        $this->expectExceptionMessage('Content-Security-Policy Endpoint called with invalid JSON data');

        Report::fromRequest(new Request([], [], [], [], [], [], 'yolo'));
    }

    public function testFromRequest()
    {
        $data = [
            'blocked-uri' => 'self',
            'effective-directive' => 'script-src',
            'script-sample' => 'try {  for(var lastpass_iter=0; lastpass',
        ];

        $report = Report::fromRequest(new Request([], [], [], [], [], [], json_encode([
            'csp-report' => $data,
        ])));

        $this->assertSame($data, $report->getData());
        $this->assertFalse($report->isData());
    }
}
