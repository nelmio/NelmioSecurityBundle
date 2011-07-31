<?php

/*
 * This file is part of the Nelmio SecurityBundle.
 *
 * (c) Nelmio <hello@nelm.io>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Nelmio\SecurityBundle\DependencyInjection;

use Symfony\Component\Config\Definition\Processor;
use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\YamlFileLoader;
use Symfony\Component\HttpKernel\DependencyInjection\Extension;

class NelmioSecurityExtension extends Extension
{
    /**
     * Parses the configuration.
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

        if (!empty($config['signed_cookie'])) {
            $loader->load('signed_cookie.yml');
            $container->setParameter('nelmio_security.signed_cookie.names', $config['signed_cookie']['names']);
            $container->setParameter('nelmio_security.signer.secret', $config['signed_cookie']['secret']);
            $container->setParameter('nelmio_security.signer.hash_algo', $config['signed_cookie']['hash_algo']);
        }

        if (!empty($config['clickjacking'])) {
            $loader->load('clickjacking.yml');
            $container->setParameter('nelmio_security.clickjacking.paths', $config['clickjacking']['paths']);
        }

        if (!empty($config['external_redirects'])) {
            $loader->load('external_redirects.yml');
            $container->setParameter('nelmio_security.external_redirects.override', $config['external_redirects']['override']);
            $container->setParameter('nelmio_security.external_redirects.abort', $config['external_redirects']['abort']);
            if ($config['external_redirects']['whitelist']) {
                $whitelist = array_map(function($el) {
                    return ltrim($el, '.');
                }, $config['external_redirects']['whitelist']);
                $whitelist = array_map('preg_quote', $whitelist);
                $whitelist = '(?:.*\.'.implode('|.*\.', $whitelist).'|'.implode('|', $whitelist).')';
                $container->setParameter('nelmio_security.external_redirects.whitelist', $whitelist);
            }
            if (!$config['external_redirects']['log']) {
                $def = $container->getDefinition('nelmio_security.external_redirect_listener');
                $def->replaceArgument(2, null);
            }
        }
    }
}
