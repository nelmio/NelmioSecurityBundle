<?php

namespace Nelmio\SecurityBundle\Tests\DependencyInjection;

use Symfony\Component\Config\Definition\Processor;
use Nelmio\SecurityBundle\DependencyInjection\Configuration;
use Symfony\Component\Yaml\Parser;

class ConfigurationTest extends \PHPUnit_Framework_TestCase
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

    public function testCspWithLevel2()
    {
        $this->processYamlConfiguration(
            "csp:\n".
            "  report:\n".
            "    script-src:\n".
            "      - 'self'\n".
            "    upgrade-insecure-requests: ~\n".
            "    block-all-mixed-content: ~\n"
        );
    }

    /**
     * @expectedException Symfony\Component\Config\Definition\Exception\InvalidConfigurationException
     * @expectedExceptionMessage Invalid configuration for path "nelmio_security.csp": "upgrade-insecure-requests" and "block-all-mixed-content" only accept an empty value "~"
     */
    public function testCspInvalidLevel2()
    {
        $this->processYamlConfiguration(
            "csp:\n".
            "  report:\n".
            "    script-src:\n".
            "      - 'self'\n".
            "    upgrade-insecure-requests:\n".
            "      - 'self'\n"
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
