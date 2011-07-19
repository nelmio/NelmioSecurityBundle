<?php

namespace Nelmio\SecurityBundle\DependencyInjection;

use Symfony\Component\Config\Definition\Processor;
use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\YamlFileLoader;
use Symfony\Component\HttpKernel\DependencyInjection\Extension;

class NelmioSecurityExtension extends Extension
{
    /**
     * Responds to the twig configuration parameter.
     *
     * @param array            $configs
     * @param ContainerBuilder $container
     */
    public function load(array $configs, ContainerBuilder $container)
    {
        $processor = new Processor();
        $configuration = new Configuration();
        $config = $processor->processConfiguration($configuration, $configs);

        $loader = new YamlFileLoader($container, new FileLocator(__DIR__.'/../Resources/config'));
        $loader->load('services.yml');

        if (!empty($config['signed_cookie'])) {
            $container->setParameter('nelmio_security.signed_cookie.names', $config['signed_cookie']['names']);
        } else {
            $container->removeDefinition('nelmio_security.signed_cookie_listener');
        }
    }
}
