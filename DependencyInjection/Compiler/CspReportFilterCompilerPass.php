<?php

namespace Nelmio\SecurityBundle\DependencyInjection\Compiler;

use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;

class CspReportFilterCompilerPass implements CompilerPassInterface
{
    public function process(ContainerBuilder $container)
    {
        $services = $container->findTaggedServiceIds('nelmio_security.csp_report_filter');

        $cspViolationLogFilterDefinition = $container->getDefinition('nelmio_security.csp_report.filter');

        foreach ($services as $id => $attributes) {
            $cspViolationLogFilterDefinition->addMethodCall('addNoiseDetector', new Reference($id));
        }
    }
}
