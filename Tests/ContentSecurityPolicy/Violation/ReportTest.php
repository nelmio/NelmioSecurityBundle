<?php

namespace Nelmio\SecurityBundle\ContentSecurityPolicy\Violation;

use Symfony\Component\HttpFoundation\Request;

class ReportTest extends \PHPUnit\Framework\TestCase
{
    public function testFromRequestWithoutData()
    {
        $this->expectException('Nelmio\SecurityBundle\ContentSecurityPolicy\Violation\Exception\NoDataException');
        $this->expectExceptionMessage('Content-Security-Policy Endpoint called without data');

        Report::fromRequest(new Request());
    }

    public function testFromRequestWithoutReportKey()
    {
        $this->expectException('Nelmio\SecurityBundle\ContentSecurityPolicy\Violation\Exception\MissingCspReportException');
        $this->expectExceptionMessage('Content-Security-Policy Endpoint called without "csp-report" data');

        Report::fromRequest(new Request(array(), array(), array(), array(), array(), array(), '{}'));
    }

    public function testFromRequestWithInvalidJSON()
    {
        $this->expectException('Nelmio\SecurityBundle\ContentSecurityPolicy\Violation\Exception\InvalidPayloadException');
        $this->expectExceptionMessage('Content-Security-Policy Endpoint called with invalid JSON data');

        Report::fromRequest(new Request(array(), array(), array(), array(), array(), array(), 'yolo'));
    }

    public function testFromRequest()
    {
        $data = array(
            'blocked-uri' => 'self',
            'effective-directive' => 'script-src',
            'script-sample' => 'try {  for(var lastpass_iter=0; lastpass',
        );

        $report = Report::fromRequest(new Request(array(), array(), array(), array(), array(), array(), json_encode(array(
            'csp-report' => $data,
        ))));

        $this->assertSame($data, $report->getData());
        $this->assertFalse($report->isData());
    }
}
