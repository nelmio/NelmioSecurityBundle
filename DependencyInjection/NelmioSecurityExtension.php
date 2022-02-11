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
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Loader\YamlFileLoader;
use Symfony\Component\DependencyInjection\Reference;
use Symfony\Component\HttpKernel\DependencyInjection\Extension;
use Symfony\Component\HttpKernel\HttpKernel;
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

        if (!empty($config['csp']) && $config['csp']['enabled']) {
            if (version_compare(Kernel::VERSION, '2.6', '>=')) {
                $loader->load('csp.yml');
            } else {
                $loader->load('csp_legacy.yml');
            }

            $cspConfig = $config['csp'];

            $enforceDefinition = $this->buildDirectiveSetDefinition($container, $cspConfig, 'enforce');
            $reportDefinition = $this->buildDirectiveSetDefinition($container, $cspConfig, 'report');

            $cspListenerDefinition = $container->getDefinition('nelmio_security.csp_listener');
            $cspListenerDefinition->setArguments(array($reportDefinition, $enforceDefinition, new Reference('nelmio_security.nonce_generator'), new Reference('nelmio_security.sha_computer'), (bool) $cspConfig['compat_headers'], $cspConfig['hosts'], $cspConfig['content_types']));
            $container->setParameter('nelmio_security.csp.hash_algorithm', $cspConfig['hash']['algorithm']);

            $cspViolationLogFilterDefinition = $container->getDefinition('nelmio_security.csp_report.filter');

            $container->setParameter('nelmio_security.csp.report_log_level', $cspConfig['report_endpoint']['log_level']);

            if (count($cspConfig['report_endpoint']['dismiss']) > 0) {
                $container->getDefinition('nelmio_security.csp_report.filter.noise_detector_custom_rules')
                    ->replaceArgument(0, $cspConfig['report_endpoint']['dismiss']);
                $cspViolationLogFilterDefinition->addMethodCall('addNoiseDetector', array(new Reference('nelmio_security.csp_report.filter.noise_detector_custom_rules')));
            }

            if ($cspConfig['report_endpoint']['filters']['domains']) {
                $cspViolationLogFilterDefinition->addMethodCall('addNoiseDetector', array(new Reference('nelmio_security.csp_report.filter.noise_detector_domains')));
                $cspViolationLogFilterDefinition->addMethodCall('addNoiseDetector', array(new Reference('nelmio_security.csp_report.filter.noise_detector_domains_regex')));
            }

            if ($cspConfig['report_endpoint']['filters']['schemes']) {
                $cspViolationLogFilterDefinition->addMethodCall('addNoiseDetector', array(new Reference('nelmio_security.csp_report.filter.noise_detector_schemes')));
            }

            if ($cspConfig['report_endpoint']['filters']['injected_scripts']) {
                $cspViolationLogFilterDefinition->addMethodCall('addNoiseDetector', array(new Reference('nelmio_security.csp_report.filter.noise_detector_injected_scripts')));
            }

            if ($cspConfig['report_endpoint']['filters']['browser_bugs']) {
                $cspViolationLogFilterDefinition->addMethodCall('addNoiseDetector', array(new Reference('nelmio_security.csp_report.filter.noise_detector_browser_bugs')));
            }

            $loggerDefinition = $container->getDefinition('nelmio_security.csp_report.logger');
            $loggerDefinition->replaceArgument(0, new Reference($cspConfig['report_logger_service']));
            $loggerDefinition->replaceArgument(1, new Reference($cspConfig['report_endpoint']['log_formatter']));

            if ($cspConfig['report_endpoint']['log_channel']) {
                $loggerDefinition->addTag('monolog.logger', array('channel' => $cspConfig['report_endpoint']['log_channel']));
            }
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
                if ($config['external_redirects']['allow_list']) {
                    throw new \LogicException('You cannot use external_redirects.whitelist and external_redirects.allow_list at the same time.');
                }

                @trigger_error(
                    'external_redirects.whitelist configuration option is deprecated since nelmio/security-bundle 2.12 and will not work in 3.0, use external_redirects.allow_list instead.',
                    E_USER_DEPRECATED
                );

                $config['external_redirects']['allow_list'] = $config['external_redirects']['whitelist'];
            }

            if ($config['external_redirects']['allow_list']) {
                $allowList = array_map(function ($el) {
                    if ($host = parse_url($el, PHP_URL_HOST)) {
                        return ltrim($host, '.');
                    }

                    return ltrim($el, '.');
                }, $config['external_redirects']['allow_list']);
                $allowList = array_map('preg_quote', $allowList);
                $allowList = '(?:.*\.'.implode('|.*\.', $allowList).'|'.implode('|', $allowList).')';
                $container->setParameter('nelmio_security.external_redirects.whitelist', $allowList);
            }
            if (!$config['external_redirects']['log']) {
                $def = $container->getDefinition('nelmio_security.external_redirect_listener');
                $def->replaceArgument(4, null);
            }
        }

        if (!empty($config['flexible_ssl']) && $config['flexible_ssl']['enabled']) {
            if (version_compare(Kernel::VERSION, '5.1', '>=')) {
                $loader->load('flexible_ssl.yml');
            } else {
                $loader->load('flexible_ssl_legacy.yml');
            }

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

            if ([] !== $config['forced_ssl']['whitelist']) {
                if ([] !== $config['forced_ssl']['allow_list']) {
                    throw new \LogicException('You cannot use forced_ssl.whitelist and forced_ssl.allow_list at the same time.');
                }

                @trigger_error(
                    'forced_ssl.whitelist configuration option is deprecated since nelmio/security-bundle 2.12 and will not work in 3.0, use forced_ssl.allow_list instead.',
                    E_USER_DEPRECATED
                );

                $config['forced_ssl']['allow_list'] = $config['forced_ssl']['whitelist'];
            }

            $container->setParameter('nelmio_security.forced_ssl.whitelist', $config['forced_ssl']['allow_list']);
            $container->setParameter('nelmio_security.forced_ssl.hosts', $config['forced_ssl']['hosts']);
            $container->setParameter('nelmio_security.forced_ssl.redirect_status_code', $config['forced_ssl']['redirect_status_code']);
        }

        if (!empty($config['referrer_policy']) && $config['referrer_policy']['enabled']) {
            $loader->load('referrer_policy.yml');
            $container->setParameter('nelmio_security.referrer_policy.policies', $config['referrer_policy']['policies']);
        }
    }

    private function buildDirectiveSetDefinition(ContainerBuilder $container, $config, $type)
    {
        $directiveDefinition = new Definition('Nelmio\SecurityBundle\ContentSecurityPolicy\DirectiveSet');

        if (version_compare(Kernel::VERSION, '2.6', '>=')) {
            $directiveDefinition->setFactory(array('Nelmio\SecurityBundle\ContentSecurityPolicy\DirectiveSet', 'fromConfig'));
        } else {
            $directiveDefinition->setFactoryClass('Nelmio\SecurityBundle\ContentSecurityPolicy\DirectiveSet');
            $directiveDefinition->setFactoryMethod('fromConfig');
        }

        $pmDefinition = $container->getDefinition('nelmio_security.policy_manager');

        if (isset($config[$type]) && $config[$type]['browser_adaptive']['enabled']) {
            $service = $config[$type]['browser_adaptive']['parser'];

            $container->setParameter('nelmio_browser_adaptive_parser', $service);

            $uaParser = $container->getDefinition('nelmio_security.ua_parser');
            $uaParser->setArguments(array(new Reference('nelmio_security.ua_parser.ua_php')));

            $pmDefinition->setArguments(array(new Reference('nelmio_security.ua_parser')));
        }

        $directiveDefinition->setArguments(array($pmDefinition, $config, $type));

        return $directiveDefinition;
    }
}
