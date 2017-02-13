<?php

namespace Nelmio\SecurityBundle\ContentSecurityPolicy\Violation;

use Symfony\Component\HttpFoundation\Request;

class ReportTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @expectedException Nelmio\SecurityBundle\ContentSecurityPolicy\Violation\Exception\NoDataException
     * @expectedExceptionMessage Content-Security-Policy Endpoint called without data
     */
    public function testFromRequestWithoutData()
    {
        Report::fromRequest(new Request());
    }

    /**
     * @expectedException Nelmio\SecurityBundle\ContentSecurityPolicy\Violation\Exception\MissingCspReportException
     * @expectedExceptionMessage Content-Security-Policy Endpoint called without "csp-report" data
     */
    public function testFromRequestWithoutReportKey()
    {
        Report::fromRequest(new Request(array(), array(), array(), array(), array(), array(), '{}'));
    }

    /**
     * @expectedException Nelmio\SecurityBundle\ContentSecurityPolicy\Violation\Exception\InvalidPayloadException
     * @expectedExceptionMessage Content-Security-Policy Endpoint called with invalid JSON data
     */
    public function testFromRequestWithInvalidJSON()
    {
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
