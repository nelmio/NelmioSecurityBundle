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
use Symfony\Component\DependencyInjection\Reference;
use Symfony\Component\HttpKernel\DependencyInjection\Extension;
use Symfony\Component\HttpKernel\Kernel;

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

        if (!empty($config['signed_cookie']['names'])) {
            $loader->load('signed_cookie.yml');
            $container->setParameter('nelmio_security.signed_cookie.names', $config['signed_cookie']['names']);
            $container->setParameter('nelmio_security.signer.secret', $config['signed_cookie']['secret']);
            $container->setParameter('nelmio_security.signer.hash_algo', $config['signed_cookie']['hash_algo']);
        }

        if (!empty($config['encrypted_cookie']['names'])) {
            $loader->load('encrypted_cookie.yml');
            $container->setParameter('nelmio_security.encrypted_cookie.names', $config['encrypted_cookie']['names']);
            $container->setParameter('nelmio_security.encrypter.secret', $config['encrypted_cookie']['secret']);
            $container->setParameter('nelmio_security.encrypter.algorithm', $config['encrypted_cookie']['algorithm']);
        }

        if (!empty($config['clickjacking'])) {
            $loader->load('clickjacking.yml');
            $container->setParameter('nelmio_security.clickjacking.paths', $config['clickjacking']['paths']);
            $container->setParameter('nelmio_security.clickjacking.content_types', $config['clickjacking']['content_types']);
        }

        if (!empty($config['csp'])) {
            if (version_compare(Kernel::VERSION, '2.6', '>=')) {
                $loader->load('csp.yml');
            } else {
                $loader->load('csp_legacy.yml');
            }

            $container->getDefinition('nelmio_security.csp_listener')
                ->setArguments(array($config['csp']));

            $container->getDefinition('nelmio_security.csp_reporter_controller')
                ->setArguments(array(new Reference($config['csp']['report_logger_service'])));
        }

        if (!empty($config['xss_protection'])) {
            if (version_compare(Kernel::VERSION, '2.6', '>=')) {
                $loader->load('xss_protection.yml');
            } else {
                $loader->load('xss_protection_legacy.yml');
            }

            $container->getDefinition('nelmio_security.xss_protection_listener')
                ->setArguments(array($config['xss_protection']));
        }

        if (!empty($config['content_type'])) {
            $loader->load('content_type.yml');
            $container->setParameter('nelmio_security.content_type.nosniff', $config['content_type']['nosniff']);
        }

        if (!empty($config['external_redirects'])) {
            $loader->load('external_redirects.yml');
            $container->setParameter('nelmio_security.external_redirects.override', $config['external_redirects']['override']);
            $container->setParameter('nelmio_security.external_redirects.forward_as', $config['external_redirects']['forward_as']);
            $container->setParameter('nelmio_security.external_redirects.abort', $config['external_redirects']['abort']);
            if ($config['external_redirects']['whitelist']) {
                $whitelist = array_map(function($el) {
                    if ($host = parse_url($el, PHP_URL_HOST)) {
                        return ltrim($host, '.');
                    }

                    return ltrim($el, '.');
                }, $config['external_redirects']['whitelist']);
                $whitelist = array_map('preg_quote', $whitelist);
                $whitelist = '(?:.*\.'.implode('|.*\.', $whitelist).'|'.implode('|', $whitelist).')';
                $container->setParameter('nelmio_security.external_redirects.whitelist', $whitelist);
            }
            if (!$config['external_redirects']['log']) {
                $def = $container->getDefinition('nelmio_security.external_redirect_listener');
                $def->replaceArgument(4, null);
            }
        }

        if (!empty($config['flexible_ssl']) && $config['flexible_ssl']['enabled']) {
            $loader->load('flexible_ssl.yml');
            $container->setParameter('nelmio_security.flexible_ssl.cookie_name', $config['flexible_ssl']['cookie_name']);
            $container->setParameter('nelmio_security.flexible_ssl.unsecured_logout', $config['flexible_ssl']['unsecured_logout']);
        }

        if (!empty($config['cookie_session']) && $config['cookie_session']['enabled']) {
            $loader->load('cookie_session.yml');
            $container->setParameter('nelmio_security.cookie_session.name', $config['cookie_session']['name']);
            $container->setParameter('nelmio_security.cookie_session.lifetime', $config['cookie_session']['lifetime']);
            $container->setParameter('nelmio_security.cookie_session.path', $config['cookie_session']['path']);
            $container->setParameter('nelmio_security.cookie_session.domain', $config['cookie_session']['domain']);
            $container->setParameter('nelmio_security.cookie_session.secure', $config['cookie_session']['secure']);
            $container->setParameter('nelmio_security.cookie_session.httponly', $config['cookie_session']['httponly']);
        }

        if (!empty($config['forced_ssl']) && $config['forced_ssl']['enabled']) {
            $loader->load('forced_ssl.yml');
            if ($config['forced_ssl']['hsts_max_age'] > 0) {
                $def = $container->getDefinition('nelmio_security.forced_ssl_listener');
                $def->addTag('kernel.event_listener', array('event' => 'kernel.response', 'method' => 'onKernelResponse'));
            }
            $container->setParameter('nelmio_security.forced_ssl.hsts_max_age', $config['forced_ssl']['hsts_max_age']);
            $container->setParameter('nelmio_security.forced_ssl.hsts_subdomains', $config['forced_ssl']['hsts_subdomains']);
            $container->setParameter('nelmio_security.forced_ssl.hsts_preload', $config['forced_ssl']['hsts_preload']);
            $container->setParameter('nelmio_security.forced_ssl.whitelist', $config['forced_ssl']['whitelist'] ?: array());
        }
    }
}
