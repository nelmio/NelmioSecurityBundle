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
        $config = $this->processYamlConfiguration(
            "csp:\n".
            "  report:\n".
            "    script-src:\n".
            "      - 'self'\n".
            "  enforce:\n".
            "    script-src:\n".
            "      - 'self'"
        );

        $this->assertIsArray($config['csp']);
        $this->assertIsArray($config['csp']['report']['script-src']);
        $this->assertIsArray($config['csp']['enforce']['script-src']);
        $this->assertSame(['self'], $config['csp']['report']['script-src']);
        $this->assertSame(['self'], $config['csp']['enforce']['script-src']);
    }

    public function testReportUriScalar(): void
    {
        $config = $this->processYamlConfiguration(
            "csp:\n".
            "  enforce:\n".
            "    report-uri: /csp/report\n"
        );

        $this->assertIsArray($config['csp']);
        $this->assertIsArray($config['csp']['enforce']['report-uri']);
        $this->assertSame(['/csp/report'], $config['csp']['enforce']['report-uri']);
    }

    public function testReportUriArray(): void
    {
        $config = $this->processYamlConfiguration(
            "csp:\n".
            "  enforce:\n".
            "    report-uri:\n".
            "      - /csp/report\n"
        );

        $this->assertIsArray($config['csp']);
        $this->assertIsArray($config['csp']['enforce']['report-uri']);
        $this->assertSame(['/csp/report'], $config['csp']['enforce']['report-uri']);
    }

    public function testReportUriValidWithMultiple(): void
    {
        $config = $this->processYamlConfiguration(
            "csp:\n".
            "  enforce:\n".
            "    report-uri:\n".
            "      - /csp/report1\n".
            "      - /csp/report2\n"
        );

        $this->assertIsArray($config['csp']);
        $this->assertIsArray($config['csp']['enforce']['report-uri']);
        $this->assertSame(['/csp/report1', '/csp/report2'], $config['csp']['enforce']['report-uri']);
    }

    public function testCspWithLevel2(): void
    {
        $config = $this->processYamlConfiguration(
            "csp:\n".
            "  report:\n".
            "    script-src:\n".
            "      - 'self'\n".
            "    upgrade-insecure-requests: false\n".
            "    block-all-mixed-content: true\n"
        );

        $this->assertIsArray($config['csp']);
        $this->assertIsArray($config['csp']['report']);
        $this->assertIsArray($config['csp']['report']['script-src']);
        $this->assertSame(['self'], $config['csp']['report']['script-src']);
        $this->assertFalse($config['csp']['report']['upgrade-insecure-requests']);
        $this->assertTrue($config['csp']['report']['block-all-mixed-content']);
    }

    public function testBrowserAdaptiveArray(): void
    {
        $config = $this->processYamlConfiguration(
            "csp:\n".
            "  report:\n".
            "    script-src:\n".
            "      - 'self'\n".
            "    browser_adaptive:\n".
            "      enabled: true\n".
            "      parser: service_name\n"
        );

        $this->assertIsArray($config['csp']);
        $this->assertIsArray($config['csp']['report']);
        $this->assertSame(['self'], $config['csp']['report']['script-src']);
        $this->assertIsArray($config['csp']['report']['script-src']);
        $this->assertIsArray($config['csp']['report']['browser_adaptive']);
        $this->assertTrue($config['csp']['report']['browser_adaptive']['enabled']);
        $this->assertSame('service_name', $config['csp']['report']['browser_adaptive']['parser']);
    }

    public function testReferrerPolicy(): void
    {
        $config = $this->processYamlConfiguration(
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

        $this->assertIsArray($config['referrer_policy']);
        $this->assertIsArray($config['referrer_policy']['policies']);
        $this->assertSame([
            'no-referrer',
            'no-referrer-when-downgrade',
            'same-origin',
            'origin',
            'strict-origin',
            'origin-when-cross-origin',
            'strict-origin-when-cross-origin',
            'unsafe-url',
            '',
        ], $config['referrer_policy']['policies']);
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
        $config = $this->processYamlConfiguration(
            "xss_protection:\n".
            "  enabled: true\n".
            "  mode_block: true\n".
            "  report_uri: https://report.com/endpoint\n"
        );

        $this->assertIsArray($config['xss_protection']);
        $this->assertTrue($config['xss_protection']['enabled']);
        $this->assertTrue($config['xss_protection']['mode_block']);
        $this->assertSame('https://report.com/endpoint', $config['xss_protection']['report_uri']);
    }

    /**
     * @return array<string, mixed>
     */
    private function processYamlConfiguration(string $config): array
    {
        $parser = new Parser();

        return $this->processYaml($parser->parse($config));
    }

    /**
     * @param mixed[] $parsedYaml
     *
     * @return array<string, mixed>
     */
    private function processYaml(array $parsedYaml): array
    {
        $processor = new Processor();
        $configDefinition = new Configuration();

        return $processor->processConfiguration($configDefinition, [$parsedYaml]);
    }
}
