<?php

namespace Nelmio\SecurityBundle\Tests\DependencyInjection;

use Symfony\Component\Config\Definition\Processor;
use Symfony\Component\Yaml\Yaml;
use Nelmio\SecurityBundle\DependencyInjection\Configuration;
use Symfony\Component\Yaml\Parser;

class ConfigurationTest extends \PHPUnit_Framework_TestCase
{
    public function testCspReportOnly()
    {
        $this->processYamlConfiguration(
            "csp:\n" .
            "  script:\n" .
            "    - 'self'\n" .
            "  report_only: true"
        );
    }

    public function testCspReportOnlyDefaultIsFalse()
    {
        $config = $this->processYamlConfiguration(
            "csp: ~"
        );
        $this->assertArrayHasKey('report_only', $config['csp']);
        $this->assertFalse($config['csp']['report_only'], 'default value for report_only config should be false');
    }

    public function testCspReportOnlyConfigIsRespectedIfPresent()
    {
        $config = $this->processYamlConfiguration(
            "csp:\n" .
            "  report_only: true"
        );
        $this->assertTrue($config['csp']['report_only']);
    }

    public function testCspWithReportAndEnforceSubtrees()
    {
        $this->processYamlConfiguration(
            "csp:\n" .
            "  report:\n" .
            "    script-src:\n" .
            "      - 'self'\n" .
            "  enforce:\n" .
            "    script-src:\n" .
            "      - 'self'"
        );
    }

    /**
     * @expectedException Symfony\Component\Config\Definition\Exception\InvalidConfigurationException
     * @expectedExceptionMessage report_only" and "(report|enforce)" can not be used together
     */
    public function testCspExclusiveReportOnlyAndEnforceSubtree()
    {
        $this->processYamlConfiguration(
            "csp:\n" .
            "  report_only:\n" .
            "  enforce:\n" .
            "    script-src:\n" .
            "      - 'self'"
        );
    }

    /**
     * @expectedException Symfony\Component\Config\Definition\Exception\InvalidConfigurationException
     * @expectedExceptionMessage report_only" and "(report|enforce)" can not be used together
     */
    public function testCspExclusiveReportOnlyAndReportSubtree()
    {
        $this->processYamlConfiguration(
            "csp:\n" .
            "  report_only:\n" .
            "  report:\n" .
            "    script-src:\n" .
            "      - 'self'"
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
        return $processor->processConfiguration($configDefinition, array($parsedYaml));
    }
}
