<?php

/*
 * This file is part of the Nelmio SecurityBundle.
 *
 * (c) Nelmio <hello@nelm.io>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Nelmio\SecurityBundle\ContentSecurityPolicy\Violation;

use Symfony\Component\HttpFoundation\Request;
use Nelmio\SecurityBundle\ContentSecurityPolicy\Violation\Exception\InvalidPayloadException;
use Nelmio\SecurityBundle\ContentSecurityPolicy\Violation\Exception\MissingCspReportException;
use Nelmio\SecurityBundle\ContentSecurityPolicy\Violation\Exception\NoDataException;

class Report
{
    private $data;

    public function __construct(array $data = array())
    {
        $this->data = $data;
    }

    public function setProperty($key, $value)
    {
        $this->data[$key] = $value;

        return $this;
    }

    public function getDirective()
    {
        if (isset($this->data['effective-directive'])) {
            return $this->data['effective-directive'];
        }

        if (isset($this->data['violated-directive'])) {
            $parts = explode(' ', $this->data['violated-directive'], 2);

            return $parts[0];
        }
    }

    public function getUri()
    {
        return isset($this->data['blocked-uri']) ? $this->data['blocked-uri'] : null;
    }

    public function getScriptSample()
    {
        return isset($this->data['script-sample']) ? $this->data['script-sample'] : null;
    }

    public function getDomain()
    {
        if (null === $uri = $this->getUri()) {
            return;
        }

        if (null !== $host = parse_url($uri, PHP_URL_HOST)) {
            return $host;
        }

        return strtolower($uri);
    }

    public function getScheme()
    {
        if (null === $uri = $this->getUri()) {
            return;
        }

        if (false === $pos = strpos($uri, '://')) {
            return;
        }

        return strtolower(substr($uri, 0, $pos));
    }

    public function isData()
    {
        if (null === $uri = $this->getUri()) {
            return false;
        }

        if (0 === strpos($uri, 'data:')) {
            return true;
        }

        return $uri === 'data';
    }

    public function getSourceFile()
    {
        return isset($this->data['source-file']) ? $this->data['source-file'] : null;
    }

    public function getData()
    {
        return $this->data;
    }

    public static function fromRequest(Request $request)
    {
        $content = $request->getContent();

        if (empty($content)) {
            throw new NoDataException('Content-Security-Policy Endpoint called without data', 411);
        }

        $json = @json_decode($content, true);

        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new InvalidPayloadException('Content-Security-Policy Endpoint called with invalid JSON data', 400);
        }

        if (!isset($json['csp-report'])) {
            throw new MissingCspReportException('Content-Security-Policy Endpoint called without "csp-report" data', 400);
        }

        $report = $json['csp-report'];

        if (empty($report) && (!isset($report['csp-report']) || !is_array($report['csp-report']))) {
            return new self();
        }

        $effective = isset($report['csp-report']['effective-directive']) ? $report['csp-report']['effective-directive'] : null;

        if (null === $effective && isset($report['csp-report']['violated-directive'])) {
            $split = explode(' ', $report['csp-report']['violated-directive']);
            $effective = isset($split[0]) ? $split[0] : null;
        }

        $blocked = isset($report['csp-report']['blocked-uri']) ? $report['csp-report']['blocked-uri'] : null;

        $ret = array(
            'effective-directive' => $effective,
            'blocked-uri' => $blocked,
        );

        if (isset($report['csp-report']['script-sample'])) {
            $ret['script-sample'] = $report['csp-report']['script-sample'];
        }

        return new self($report);
    }
}
