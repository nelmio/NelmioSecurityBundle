<?php

namespace Nelmio\SecurityBundle\DependencyInjection\Compiler;

use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;

class CspReportFilterCompilerPass implements CompilerPassInterface
{
    public function process(ContainerBuilder $container)
    {
        if (!$container->hasDefinition('nelmio_security.csp_report.filter')) {
            return;
        }
        
        $services = $container->findTaggedServiceIds('nelmio_security.csp_report_filter');

        $cspViolationLogFilterDefinition = $container->getDefinition('nelmio_security.csp_report.filter');

        foreach ($services as $id => $attributes) {
            $cspViolationLogFilterDefinition->addMethodCall('addNoiseDetector', array(new Reference($id)));
        }
    }
}
