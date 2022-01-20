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

use Nelmio\SecurityBundle\ContentSecurityPolicy\Violation\Exception\InvalidPayloadException;
use Nelmio\SecurityBundle\ContentSecurityPolicy\Violation\Exception\MissingCspReportException;
use Nelmio\SecurityBundle\ContentSecurityPolicy\Violation\Exception\NoDataException;
use Symfony\Component\HttpFoundation\Request;

class Report
{
    private $data;

    public function __construct(array $data = [])
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
        return $this->data['blocked-uri'] ?? null;
    }

    public function getScriptSample()
    {
        return $this->data['script-sample'] ?? null;
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

        return 'data' === $uri;
    }

    public function getSourceFile()
    {
        return $this->data['source-file'] ?? null;
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

        if (JSON_ERROR_NONE !== json_last_error()) {
            throw new InvalidPayloadException('Content-Security-Policy Endpoint called with invalid JSON data', 400);
        }

        if (!isset($json['csp-report'])) {
            throw new MissingCspReportException('Content-Security-Policy Endpoint called without "csp-report" data', 400);
        }

        $report = $json['csp-report'];

        if (empty($report) && (!isset($report['csp-report']) || !is_array($report['csp-report']))) {
            return new self();
        }

        $effective = $report['csp-report']['effective-directive'] ?? null;

        if (null === $effective && isset($report['csp-report']['violated-directive'])) {
            $split = explode(' ', $report['csp-report']['violated-directive']);
            $effective = $split[0] ?? null;
        }

        $blocked = $report['csp-report']['blocked-uri'] ?? null;

        $ret = [
            'effective-directive' => $effective,
            'blocked-uri' => $blocked,
        ];

        if (isset($report['csp-report']['script-sample'])) {
            $ret['script-sample'] = $report['csp-report']['script-sample'];
        }

        return new self($report);
    }
}
