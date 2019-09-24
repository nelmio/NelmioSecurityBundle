<?php

namespace Nelmio\SecurityBundle\DependencyInjection\Compiler;

use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\Reference;

class UAParserCompilerPass implements CompilerPassInterface
{
    public function process(ContainerBuilder $container)
    {
        if (!$container->hasParameter('nelmio_browser_adaptive_parser')) {
            return;
        }

        $container
            ->getDefinition('nelmio_security.ua_parser')
            ->setArguments(array(new Reference($container->getParameter('nelmio_browser_adaptive_parser'))));
    }
}
