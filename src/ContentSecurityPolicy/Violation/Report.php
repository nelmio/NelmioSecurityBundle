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

/**
 * @phpstan-type ReportData array{document-uri?: string, referrer?: string, blocked-uri?: string, effective-directive?: string, violated-directive?: string, original-policy?: string, disposition?: string, status-code?: int, script-sample?: string, source-file?: string, line-number?: int, column-number?: int}
 */
final class Report
{
    /**
     * @var array<string, int|string>
     *
     * @phpstan-var ReportData
     */
    private array $data;

    private ?string $userAgent;

    /**
     * @param array<string, string> $data
     *
     * @phpstan-param ReportData $data
     */
    public function __construct(array $data = [], ?string $userAgent = null)
    {
        $this->data = $data;
        $this->userAgent = $userAgent;
    }

    /**
     * @param string|int $value
     *
     * @phpstan-template K of key-of<ReportData>
     *
     * @phpstan-param K $key
     * @phpstan-param ReportData[K] $value
     */
    public function setProperty(string $key, $value): self
    {
        if (!\is_string($value) && !\is_int($value)) {
            throw new \TypeError('Expected string or int, got '.\gettype($value));
        }
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

        $host = parse_url($uri, \PHP_URL_HOST);

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
     * @return array<string, int|string>
     *
     * @phpstan-return ReportData
     */
    public function getData(): array
    {
        return $this->data;
    }

    public function getUserAgent(): ?string
    {
        return $this->userAgent;
    }

    public static function fromRequest(Request $request): self
    {
        $content = $request->getContent();

        if ('' === $content) {
            throw new NoDataException('Content-Security-Policy Endpoint called without data', 411);
        }

        $json = @json_decode($content, true);

        if (\JSON_ERROR_NONE !== json_last_error()) {
            throw new InvalidPayloadException('Content-Security-Policy Endpoint called with invalid JSON data', 400);
        }

        if (!\is_array($json) || !isset($json['csp-report'])) {
            throw new MissingCspReportException('Content-Security-Policy Endpoint called without "csp-report" data', 400);
        }

        $report = $json['csp-report'];

        if (!\is_array($report) || [] === $report) {
            return new self();
        }

        $effective = $report['effective-directive'] ?? null;

        if (null === $effective && isset($report['violated-directive'])) {
            $split = explode(' ', $report['violated-directive']);
            $effective = $split[0] ?? null;
        }

        $blocked = $report['blocked-uri'] ?? null;

        $report['effective-directive'] = $effective;
        $report['blocked-uri'] = $blocked;

        return new self($report, $request->headers->get('User-Agent'));
    }
}
