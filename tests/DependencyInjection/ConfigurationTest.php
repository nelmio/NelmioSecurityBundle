<?php

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
use Symfony\Component\Config\Definition\Processor;
use Symfony\Component\Yaml\Parser;

class ConfigurationTest extends \PHPUnit\Framework\TestCase
{
    public function testCspWithReportAndEnforceSubtrees()
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

    public function testReportUriScalar()
    {
        $this->processYamlConfiguration(
            "csp:\n".
            "  enforce:\n".
            "    report-uri: /csp/report\n"
        );
    }

    public function testReportUriArray()
    {
        $this->processYamlConfiguration(
            "csp:\n".
            "  enforce:\n".
            "    report-uri:\n".
            "      - /csp/report\n"
        );
    }

    public function testReportUriValidWithMultiple()
    {
        $this->processYamlConfiguration(
            "csp:\n".
            "  enforce:\n".
            "    report-uri:\n".
            "      - /csp/report1\n".
            "      - /csp/report2\n"
        );
    }

    public function testCspWithLevel2()
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

    /**
     * @group legacy
     * @expectedDeprecation browser_adaptive configuration is now an array. Using boolean is deprecated and will not be supported anymore in version 3
     */
    public function testBrowserAdaptiveBoolean()
    {
        $this->processYamlConfiguration(
            "csp:\n".
            "  report:\n".
            "    script-src:\n".
            "      - 'self'\n".
            "    browser_adaptive: true\n"
        );
    }

    public function testBrowserAdaptiveArray()
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

    public function testReferrerPolicy()
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

    public function testReferrerPolicyInvalid()
    {
        $this->expectException('Symfony\Component\Config\Definition\Exception\InvalidConfigurationException');

        $this->processYamlConfiguration(
            "referrer_policy:\n".
            "  enabled: true\n".
            "  policies:\n".
            "    - 'no-referrer'\n".
            "    - 'foo'\n"
        );
    }

    public function testXssProtection()
    {
        $this->processYamlConfiguration(
            "xss_protection:\n".
            "  enabled: true\n".
            "  mode_block: true\n".
            "  report_uri: https://report.com/endpoint\n"
        );
    }

    private function processYamlConfiguration($config)
    {
        $parser = new Parser();

        return $this->processYaml($parser->parse($config));
    }

    private function processYaml($parsedYaml)
    {
        $processor = new Processor();
        $configDefinition = new Configuration();

        $processed = $processor->processConfiguration($configDefinition, array($parsedYaml));

        // if we passed without exception, the test is good
        $this->assertTrue(true);
    }
}
