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

use Nelmio\SecurityBundle\ContentSecurityPolicy\NonceGenerator;
use Nelmio\SecurityBundle\ContentSecurityPolicy\PolicyManager;
use Nelmio\SecurityBundle\ContentSecurityPolicy\ShaComputer;
use Nelmio\SecurityBundle\ContentSecurityPolicy\Violation\Filter\BrowserBugsNoiseDetector;
use Nelmio\SecurityBundle\ContentSecurityPolicy\Violation\Filter\CustomRulesNoiseDetector;
use Nelmio\SecurityBundle\ContentSecurityPolicy\Violation\Filter\DomainsNoiseDetector;
use Nelmio\SecurityBundle\ContentSecurityPolicy\Violation\Filter\DomainsRegexNoiseDetector;
use Nelmio\SecurityBundle\ContentSecurityPolicy\Violation\Filter\Filter;
use Nelmio\SecurityBundle\ContentSecurityPolicy\Violation\Filter\InjectedScriptsNoiseDetector;
use Nelmio\SecurityBundle\ContentSecurityPolicy\Violation\Filter\SchemesNoiseDetector;
use Nelmio\SecurityBundle\ContentSecurityPolicy\Violation\Log\LogFormatter;
use Nelmio\SecurityBundle\ContentSecurityPolicy\Violation\Log\Logger;
use Nelmio\SecurityBundle\Controller\ContentSecurityPolicyController;
use Nelmio\SecurityBundle\EventListener\ContentSecurityPolicyListener;
use Nelmio\SecurityBundle\Twig\CSPRuntime;
use Nelmio\SecurityBundle\Twig\NelmioCSPTwigExtension;
use Nelmio\SecurityBundle\UserAgent\UAFamilyParser\UAFamilyParser;
use Nelmio\SecurityBundle\UserAgent\UserAgentParser;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\DependencyInjection\Loader\Configurator\ReferenceConfigurator;
use UAParser\Parser;

return static function (ContainerConfigurator $containerConfigurator): void {
    $containerConfigurator->parameters()
        ->set('nelmio_security.nonce_generator.number_of_bytes', 16);

    $containerConfigurator->services()
        ->set('nelmio_security.ua_parser', UserAgentParser::class)

        ->set('nelmio_security.ua_parser.ua_php', UAFamilyParser::class)
            ->args([
                new ReferenceConfigurator('nelmio_security.ua_parser.ua_php.provider'),
            ])

        ->set('nelmio_security.ua_parser.ua_php.provider', Parser::class)
            ->factory([Parser::class, 'create'])

        ->set('nelmio_security.policy_manager', PolicyManager::class)

        ->set('nelmio_security.csp_listener', ContentSecurityPolicyListener::class)
            ->tag('kernel.event_subscriber')

        ->set('nelmio_security.csp_report.filter', Filter::class)

        ->set('nelmio_security.csp_report.filter.noise_detector_schemes', SchemesNoiseDetector::class)

        ->set('nelmio_security.csp_report.filter.noise_detector_domains_regex', DomainsRegexNoiseDetector::class)

        ->set('nelmio_security.csp_report.filter.noise_detector_domains', DomainsNoiseDetector::class)

        ->set('nelmio_security.csp_report.filter.noise_detector_custom_rules', CustomRulesNoiseDetector::class)
            ->args([
                [],
            ])

        ->set('nelmio_security.csp_report.filter.noise_detector_injected_scripts', InjectedScriptsNoiseDetector::class)

        ->set('nelmio_security.csp_report.filter.noise_detector_browser_bugs', BrowserBugsNoiseDetector::class)
            ->args([
                new ReferenceConfigurator('nelmio_security.ua_parser.ua_php.provider'),
            ])

        ->set('nelmio_security.csp_report.log_formatter', LogFormatter::class)

        ->set('nelmio_security.csp_report.logger', Logger::class)
            ->args([
                new ReferenceConfigurator('logger'),
                new ReferenceConfigurator('nelmio_security.csp_report.log_formatter'),
                '%nelmio_security.csp.report_log_level%',
            ])

        ->set('nelmio_security.csp_reporter_controller', ContentSecurityPolicyController::class)
        ->public()
        ->args([
            new ReferenceConfigurator('nelmio_security.csp_report.logger'),
            new ReferenceConfigurator('event_dispatcher'),
            new ReferenceConfigurator('nelmio_security.csp_report.filter'),
        ])

        ->set('nelmio_security.nonce_generator', NonceGenerator::class)
            ->args([
                '%nelmio_security.nonce_generator.number_of_bytes%',
            ])

        ->set('nelmio_security.sha_computer', ShaComputer::class)
            ->args([
                '%nelmio_security.csp.hash_algorithm%',
            ])

        ->set('nelmio_security.twig_extension', NelmioCSPTwigExtension::class)
            ->args([
                new ReferenceConfigurator('nelmio_security.sha_computer'),
            ])
            ->tag('twig.extension')

        ->set('nelmio_security.csp.runtime', CSPRuntime::class)
            ->args([
                new ReferenceConfigurator('nelmio_security.csp_listener'),
            ])
            ->tag('twig.runtime')
    ;
};
