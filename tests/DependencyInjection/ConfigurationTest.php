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

namespace Nelmio\SecurityBundle\Tests\DependencyInjection;

use Nelmio\SecurityBundle\DependencyInjection\Configuration;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\Config\Definition\Processor;
use Symfony\Component\Yaml\Parser;

class ConfigurationTest extends TestCase
{
    public function testCspWithReportAndEnforceSubtrees(): void
    {
        $this->processYamlConfiguration(
            "csp:\n".
            "  report:\n".
            "    script-src:\n".
            "      - 'self'\n".
            "  enforce:\n".
            "    script-src:\n".
            "      - 'self'"
        );
    }

    public function testReportUriScalar(): void
    {
        $this->processYamlConfiguration(
            "csp:\n".
            "  enforce:\n".
            "    report-uri: /csp/report\n"
        );
    }

    public function testReportUriArray(): void
    {
        $this->processYamlConfiguration(
            "csp:\n".
            "  enforce:\n".
            "    report-uri:\n".
            "      - /csp/report\n"
        );
    }

    public function testReportUriValidWithMultiple(): void
    {
        $this->processYamlConfiguration(
            "csp:\n".
            "  enforce:\n".
            "    report-uri:\n".
            "      - /csp/report1\n".
            "      - /csp/report2\n"
        );
    }

    public function testCspWithLevel2(): void
    {
        $this->processYamlConfiguration(
            "csp:\n".
            "  report:\n".
            "    script-src:\n".
            "      - 'self'\n".
            "    upgrade-insecure-requests: false\n".
            "    block-all-mixed-content: true\n"
        );
    }

    public function testBrowserAdaptiveArray(): void
    {
        $this->processYamlConfiguration(
            "csp:\n".
            "  report:\n".
            "    script-src:\n".
            "      - 'self'\n".
            "    browser_adaptive:\n".
            "      enabled: true\n".
            "      parser: service_name\n"
        );
    }

    public function testReferrerPolicy(): void
    {
        $this->processYamlConfiguration(
            "referrer_policy:\n".
            "  enabled: true\n".
            "  policies:\n".
            "    - 'no-referrer'\n".
            "    - 'no-referrer-when-downgrade'\n".
            "    - 'same-origin'\n".
            "    - 'origin'\n".
            "    - 'strict-origin'\n".
            "    - 'origin-when-cross-origin'\n".
            "    - 'strict-origin-when-cross-origin'\n".
            "    - 'unsafe-url'\n".
            "    - ''\n"
        );
    }

    public function testReferrerPolicyInvalid(): void
    {
        $this->expectException(InvalidConfigurationException::class);

        $this->processYamlConfiguration(
            "referrer_policy:\n".
            "  enabled: true\n".
            "  policies:\n".
            "    - 'no-referrer'\n".
            "    - 'foo'\n"
        );
    }

    public function testXssProtection(): void
    {
        $this->processYamlConfiguration(
            "xss_protection:\n".
            "  enabled: true\n".
            "  mode_block: true\n".
            "  report_uri: https://report.com/endpoint\n"
        );
    }

    private function processYamlConfiguration(string $config): void
    {
        $parser = new Parser();

        $this->processYaml($parser->parse($config));
    }

    /**
     * @param mixed[] $parsedYaml
     */
    private function processYaml(array $parsedYaml): void
    {
        $processor = new Processor();
        $configDefinition = new Configuration();

        $processed = $processor->processConfiguration($configDefinition, [$parsedYaml]);

        // if we passed without exception, the test is good
        $this->assertTrue(true);
    }
}
