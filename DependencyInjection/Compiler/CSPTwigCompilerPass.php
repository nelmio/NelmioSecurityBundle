<?php

namespace Nelmio\SecurityBundle\DependencyInjection\Compiler;

use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Reference;

class CSPTwigCompilerPass implements CompilerPassInterface
{
    public function process(ContainerBuilder $container)
    {
        if (!$container->hasDefinition('nelmio_security.csp_listener') || !$container->hasDefinition('twig')) {
            return;
        }

        $extension = new Definition('Nelmio\SecurityBundle\Twig\NelmioCSPTwigExtension');
        $extension->setArguments(array(new Reference('nelmio_security.csp_listener'), new Reference('nelmio_security.sha_computer')));

        $twig = $container->getDefinition('twig');
        $twig->addMethodCall('addExtension', [$extension]);
    }
}
