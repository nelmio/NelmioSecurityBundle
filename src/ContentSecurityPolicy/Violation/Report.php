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

namespace Nelmio\SecurityBundle\ContentSecurityPolicy\Violation;

use Nelmio\SecurityBundle\ContentSecurityPolicy\Violation\Exception\InvalidPayloadException;
use Nelmio\SecurityBundle\ContentSecurityPolicy\Violation\Exception\MissingCspReportException;
use Nelmio\SecurityBundle\ContentSecurityPolicy\Violation\Exception\NoDataException;
use Symfony\Component\HttpFoundation\Request;

class Report
{
    /**
     * @var array<string, string>
     */
    private array $data;

    /**
     * @param array<string, string> $data
     */
    public function __construct(array $data = [])
    {
        $this->data = $data;
    }

    public function setProperty(string $key, string $value): self
    {
        $this->data[$key] = $value;

        return $this;
    }

    public function getDirective(): ?string
    {
        if (isset($this->data['effective-directive'])) {
            return $this->data['effective-directive'];
        }

        if (isset($this->data['violated-directive'])) {
            $parts = explode(' ', $this->data['violated-directive'], 2);

            return $parts[0];
        }

        return null;
    }

    public function getUri(): ?string
    {
        return $this->data['blocked-uri'] ?? null;
    }

    public function getScriptSample(): ?string
    {
        return $this->data['script-sample'] ?? null;
    }

    public function getDomain(): ?string
    {
        if (null === $uri = $this->getUri()) {
            return null;
        }

        $host = parse_url($uri, PHP_URL_HOST);

        if (null !== $host && false !== $host) {
            return $host;
        }

        return strtolower($uri);
    }

    public function getScheme(): ?string
    {
        if (null === $uri = $this->getUri()) {
            return null;
        }

        if (false === $pos = strpos($uri, '://')) {
            return null;
        }

        return strtolower(substr($uri, 0, $pos));
    }

    public function isData(): bool
    {
        if (null === $uri = $this->getUri()) {
            return false;
        }

        if (0 === strpos($uri, 'data:')) {
            return true;
        }

        return 'data' === $uri;
    }

    public function getSourceFile(): ?string
    {
        return $this->data['source-file'] ?? null;
    }

    /**
     * @return array<string, string>
     */
    public function getData(): array
    {
        return $this->data;
    }

    public static function fromRequest(Request $request): self
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
