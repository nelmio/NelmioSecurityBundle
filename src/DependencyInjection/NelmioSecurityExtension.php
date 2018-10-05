<?php

declare(strict_types=1);

/*
 * This file is part of the Nelmio SecurityBundle.
 *
 * (c) Nelmio <hello@nelm.io>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Nelmio\SecurityBundle\DependencyInjection;

use Nelmio\SecurityBundle\ContentSecurityPolicy\DirectiveSet;
use Symfony\Component\Config\Definition\Processor;
use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Loader\PhpFileLoader;
use Symfony\Component\DependencyInjection\Reference;
use Symfony\Component\HttpKernel\DependencyInjection\Extension;
use Symfony\Component\HttpKernel\Kernel;

final class NelmioSecurityExtension extends Extension
{
    public function load(array $configs, ContainerBuilder $container): void
    {
        $processor = new Processor();
        $configuration = new Configuration();
        $config = $processor->processConfiguration($configuration, $configs);
        $loader = new PhpFileLoader($container, new FileLocator(__DIR__.'/../Resources/config'));

        if (isset($config['signed_cookie']['names']) && [] !== $config['signed_cookie']['names']) {
            $loader->load('signed_cookie.php');
            $container->setParameter('nelmio_security.signed_cookie.names', $config['signed_cookie']['names']);
            $container->setParameter('nelmio_security.signer.secret', $config['signed_cookie']['secret']);
            $container->setParameter('nelmio_security.signer.hash_algo', $config['signed_cookie']['hash_algo']);
        }

        if (isset($config['clickjacking']) && [] !== $config['clickjacking']) {
            $loader->load('clickjacking.php');
            $container->setParameter('nelmio_security.clickjacking.paths', $config['clickjacking']['paths']);
            $container->setParameter('nelmio_security.clickjacking.hosts', $config['clickjacking']['hosts']);
            $container->setParameter('nelmio_security.clickjacking.content_types', $config['clickjacking']['content_types']);
        }

        if ($this->isConfigEnabled($container, $config['csp'])) {
            $loader->load('csp.php');

            $cspConfig = $config['csp'];

            $enforceDefinition = $this->buildDirectiveSetDefinition($container, $cspConfig, 'enforce');
            $reportDefinition = $this->buildDirectiveSetDefinition($container, $cspConfig, 'report');

            $cspListenerDefinition = $container->getDefinition('nelmio_security.csp_listener');
            $cspListenerDefinition->setArguments([$reportDefinition, $enforceDefinition, new Reference('nelmio_security.nonce_generator'), new Reference('nelmio_security.sha_computer'), (bool) $cspConfig['compat_headers'], $cspConfig['hosts'], $cspConfig['content_types']]);
            $container->setParameter('nelmio_security.csp.hash_algorithm', $cspConfig['hash']['algorithm']);

            $cspViolationLogFilterDefinition = $container->getDefinition('nelmio_security.csp_report.filter');

            $container->setParameter('nelmio_security.csp.report_log_level', $cspConfig['report_endpoint']['log_level']);

            if (\count($cspConfig['report_endpoint']['dismiss']) > 0) {
                $container->getDefinition('nelmio_security.csp_report.filter.noise_detector_custom_rules')
                    ->replaceArgument(0, $cspConfig['report_endpoint']['dismiss']);
                $cspViolationLogFilterDefinition->addMethodCall('addNoiseDetector', [new Reference('nelmio_security.csp_report.filter.noise_detector_custom_rules')]);
            }

            if ($cspConfig['report_endpoint']['filters']['domains']) {
                $cspViolationLogFilterDefinition->addMethodCall('addNoiseDetector', [new Reference('nelmio_security.csp_report.filter.noise_detector_domains')]);
                $cspViolationLogFilterDefinition->addMethodCall('addNoiseDetector', [new Reference('nelmio_security.csp_report.filter.noise_detector_domains_regex')]);
            }

            if ($cspConfig['report_endpoint']['filters']['schemes']) {
                $cspViolationLogFilterDefinition->addMethodCall('addNoiseDetector', [new Reference('nelmio_security.csp_report.filter.noise_detector_schemes')]);
            }

            if ($cspConfig['report_endpoint']['filters']['injected_scripts']) {
                $cspViolationLogFilterDefinition->addMethodCall('addNoiseDetector', [new Reference('nelmio_security.csp_report.filter.noise_detector_injected_scripts')]);
            }

            if ($cspConfig['report_endpoint']['filters']['browser_bugs']) {
                $cspViolationLogFilterDefinition->addMethodCall('addNoiseDetector', [new Reference('nelmio_security.csp_report.filter.noise_detector_browser_bugs')]);
            }

            $loggerDefinition = $container->getDefinition('nelmio_security.csp_report.logger');
            $loggerDefinition->replaceArgument(0, new Reference($cspConfig['report_logger_service']));
            $loggerDefinition->replaceArgument(1, new Reference($cspConfig['report_endpoint']['log_formatter']));

            if ($cspConfig['report_endpoint']['log_channel']) {
                $loggerDefinition->addTag('monolog.logger', ['channel' => $cspConfig['report_endpoint']['log_channel']]);
            }
        }

        if (isset($config['xss_protection']) && [] !== $config['xss_protection']) {
            $loader->load('xss_protection.php');

            $container->getDefinition('nelmio_security.xss_protection_listener')
                ->setArguments([$config['xss_protection']]);
        }

        if (isset($config['content_type']) && [] !== $config['content_type']) {
            $loader->load('content_type.php');
            $container->setParameter('nelmio_security.content_type.nosniff', $config['content_type']['nosniff']);
        }

        if (isset($config['external_redirects']) && [] !== $config['external_redirects']) {
            $loader->load('external_redirects.php');
            $container->setParameter('nelmio_security.external_redirects.override', $config['external_redirects']['override']);
            $container->setParameter('nelmio_security.external_redirects.forward_as', $config['external_redirects']['forward_as']);
            $container->setParameter('nelmio_security.external_redirects.abort', $config['external_redirects']['abort']);

            if ($config['external_redirects']['allow_list']) {
                $allowList = array_map(static function (string $el): string {
                    $host = parse_url($el, \PHP_URL_HOST);
                    if (\is_string($host)) {
                        return ltrim($host, '.');
                    }

                    return ltrim($el, '.');
                }, $config['external_redirects']['allow_list']);
                $allowList = array_map('preg_quote', $allowList);
                $allowList = '(?:.*\.'.implode('|.*\.', $allowList).'|'.implode('|', $allowList).')';
                $container->setParameter('nelmio_security.external_redirects.allow_list', $allowList);
            }
            if (!$config['external_redirects']['log']) {
                $def = $container->getDefinition('nelmio_security.external_redirect_listener');
                $def->replaceArgument(4, null);
            }
        }

        if ($this->isConfigEnabled($container, $config['flexible_ssl'])) {
            if (version_compare(Kernel::VERSION, '5.1', '<')) {
                $loader->load('flexible_ssl_legacy.php');
            } else {
                $loader->load('flexible_ssl.php');
            }

            $container->setParameter('nelmio_security.flexible_ssl.cookie_name', $config['flexible_ssl']['cookie_name']);
            $container->setParameter('nelmio_security.flexible_ssl.unsecured_logout', $config['flexible_ssl']['unsecured_logout']);
        }

        if ($this->isConfigEnabled($container, $config['forced_ssl'])) {
            $loader->load('forced_ssl.php');
            if ($config['forced_ssl']['hsts_max_age'] > 0) {
                $def = $container->getDefinition('nelmio_security.forced_ssl_listener');
                $def->addTag('kernel.event_listener', ['event' => 'kernel.response', 'method' => 'onKernelResponse']);
            }
            $container->setParameter('nelmio_security.forced_ssl.hsts_max_age', $config['forced_ssl']['hsts_max_age']);
            $container->setParameter('nelmio_security.forced_ssl.hsts_subdomains', $config['forced_ssl']['hsts_subdomains']);
            $container->setParameter('nelmio_security.forced_ssl.hsts_preload', $config['forced_ssl']['hsts_preload']);
            $container->setParameter('nelmio_security.forced_ssl.allow_list', $config['forced_ssl']['allow_list']);
            $container->setParameter('nelmio_security.forced_ssl.hosts', $config['forced_ssl']['hosts']);
            $container->setParameter('nelmio_security.forced_ssl.redirect_status_code', $config['forced_ssl']['redirect_status_code']);
        }

        if ($this->isConfigEnabled($container, $config['referrer_policy'])) {
            $loader->load('referrer_policy.php');
            $container->setParameter('nelmio_security.referrer_policy.policies', $config['referrer_policy']['policies']);
        }
    }

    /**
     * @phpstan-param array{
     *  enforce?: array{
     *      browser_adaptive: array{
     *          enabled: bool,
     *          parser: string
     *      }
     *  },
     *  report?: array{
     *      browser_adaptive: array{
     *          enabled: bool,
     *          parser: string
     *      }
     *  }
     * } $config
     * @phpstan-param 'enforce'|'report' $type
     */
    private function buildDirectiveSetDefinition(ContainerBuilder $container, array $config, string $type): Definition
    {
        $directiveDefinition = new Definition(DirectiveSet::class);

        $directiveDefinition->setFactory([DirectiveSet::class, 'fromConfig']);

        $pmDefinition = $container->getDefinition('nelmio_security.policy_manager');

        if (isset($config[$type]) && $config[$type]['browser_adaptive']['enabled']) {
            $service = $config[$type]['browser_adaptive']['parser'];

            $container->setParameter('nelmio_browser_adaptive_parser', $service);

            $uaParser = $container->getDefinition('nelmio_security.ua_parser');
            $uaParser->setArguments([new Reference('nelmio_security.ua_parser.ua_php')]);

            $pmDefinition->setArguments([new Reference('nelmio_security.ua_parser')]);
        }

        $directiveDefinition->setArguments([$pmDefinition, $config, $type]);

        return $directiveDefinition;
    }
}
