<?php

namespace Nelmio\SecurityBundle\Tests\DependencyInjection;

use Symfony\Component\Config\Definition\Processor;
use Symfony\Component\Yaml\Yaml;
use Nelmio\SecurityBundle\DependencyInjection\Configuration;
use Symfony\Component\Yaml\Parser;

class ConfigurationTest extends \PHPUnit_Framework_TestCase
{
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
