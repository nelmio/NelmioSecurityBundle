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
use Nelmio\SecurityBundle\PermissionsPolicy\Mapping;
use Psr\Log\LogLevel;
use Symfony\Component\Config\Definition\Builder\ArrayNodeDefinition;
use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;

final class Configuration implements ConfigurationInterface
{
    /**
     * @var list<string>
     */
    private array $referrerPolicies = [
        'no-referrer',
        'no-referrer-when-downgrade',
        'same-origin',
        'origin',
        'strict-origin',
        'origin-when-cross-origin',
        'strict-origin-when-cross-origin',
        'unsafe-url',
        '',
    ];

    public function getConfigTreeBuilder(): TreeBuilder
    {
        $treeBuilder = new TreeBuilder('nelmio_security', 'array');
        $rootNode = $treeBuilder->getRootNode();

        $rootNode
            ->validate()
                ->ifTrue(static function (array $v): bool {
                    return $v['forced_ssl']['enabled'] && $v['flexible_ssl']['enabled'];
                })
                ->thenInvalid('"forced_ssl" and "flexible_ssl" can not be used together')
            ->end()
            ->children()
                ->append($this->getSignedCookiesNode())

                ->append($this->getClickjackingNode())

                ->append($this->getExternalRedirectsNode())

                ->append($this->getFlexibleSslNode())

                ->append($this->getForcedSslNode())

                ->append($this->getContentTypeNode())

                ->append($this->getXssProtectionNode())

                ->append($this->addCspNode())

                ->append($this->addReferrerPolicyNode())

                ->append($this->addPermissionsPolicyNode())
            ->end()
        ->end();

        return $treeBuilder;
    }

    private function addCspNode(): ArrayNodeDefinition
    {
        $builder = new TreeBuilder('csp');
        $node = $builder->getRootNode();

        $node
            ->canBeDisabled()
            // CSP is enabled by default to ensure BC
            ->children()
                ->scalarNode('request_matcher')->defaultNull()->end()
                ->arrayNode('hosts')->scalarPrototype()->end()->defaultValue([])->end()
                ->arrayNode('content_types')->scalarPrototype()->end()->defaultValue([])->end()
                ->arrayNode('report_endpoint')
                    ->addDefaultsIfNotSet()
                    ->children()
                        ->scalarNode('log_channel')
                            ->defaultValue(null)
                        ->end()
                        ->scalarNode('log_formatter')
                            ->defaultValue('nelmio_security.csp_report.log_formatter')
                        ->end()
                        ->enumNode('log_level')
                            ->values([
                                LogLevel::ALERT,
                                LogLevel::CRITICAL,
                                LogLevel::DEBUG,
                                LogLevel::EMERGENCY,
                                LogLevel::ERROR,
                                LogLevel::INFO,
                                LogLevel::NOTICE,
                                LogLevel::WARNING,
                            ])
                            ->defaultValue(LogLevel::NOTICE)
                        ->end()
                        ->arrayNode('filters')
                            ->addDefaultsIfNotSet()
                            ->children()
                                ->booleanNode('domains')->defaultTrue()->end()
                                ->booleanNode('schemes')->defaultTrue()->end()
                                ->booleanNode('browser_bugs')->defaultTrue()->end()
                                ->booleanNode('injected_scripts')->defaultTrue()->end()
                            ->end()
                        ->end()
                        ->arrayNode('dismiss')
                            ->normalizeKeys(false)
                            ->arrayPrototype()
                                ->beforeNormalization()
                                ->always(static function ($v): array {
                                    if (!\is_array($v)) {
                                        return [$v];
                                    }

                                    return $v;
                                })
                                ->end()
                                ->enumPrototype()
                                    ->values(array_merge(array_keys(DirectiveSet::getNames()), ['*']))
                                ->end()
                            ->end()
                        ->end()
                    ->end()
                ->end()
                // leaving this enabled can cause issues with older iOS (5.x) versions
                // and possibly other early CSP implementations
                ->booleanNode('compat_headers')->defaultValue(true)->end()
                ->scalarNode('report_logger_service')->defaultValue('logger')->end()
                ->arrayNode('hash')
                    ->addDefaultsIfNotSet()
                    ->children()
                        ->enumNode('algorithm')
                            ->info('The algorithm to use for hashes')
                            ->values(['sha256', 'sha384', 'sha512'])
                            ->defaultValue('sha256')
                        ->end()
                    ->end()
                ->end()
                ->append($this->addReportOrEnforceNode('report'))
                ->append($this->addReportOrEnforceNode('enforce'))
            ->end();

        return $node;
    }

    private function addReportOrEnforceNode(string $reportOrEnforce): ArrayNodeDefinition
    {
        $builder = new TreeBuilder($reportOrEnforce);
        $node = $builder->getRootNode();

        $children = $node->children();
        // Symfony should not normalize dashes to underlines, e.g. img-src to img_src
        $node->normalizeKeys(false);

        $children
            ->booleanNode('level1_fallback')
                ->info('Provides CSP Level 1 fallback when using hash or nonce (CSP level 2) by adding \'unsafe-inline\' source. See https://www.w3.org/TR/CSP2/#directive-script-src and https://www.w3.org/TR/CSP2/#directive-style-src')
                ->defaultValue(true)
            ->end();

        $children
            ->arrayNode('browser_adaptive')
                ->canBeEnabled()
                ->info('Do not send directives that browser do not support')
                ->addDefaultsIfNotSet()
                ->children()
                    ->scalarNode('parser')
                        ->defaultValue('nelmio_security.ua_parser.ua_php')
                    ->end()
                ->end()
            ->end();

        foreach (DirectiveSet::getNames() as $name => $type) {
            if (DirectiveSet::TYPE_NO_VALUE === $type) {
                $children
                    ->booleanNode($name)
                    ->defaultFalse()
                    ->end();
            } elseif ('report-uri' === $name) {
                $children
                    ->arrayNode($name)
                        ->scalarPrototype()->end()
                        ->beforeNormalization()
                            ->ifString()
                            ->then(static function (string $value): array { return [$value]; })
                        ->end()
                    ->end();
            } elseif (\in_array($type, [DirectiveSet::TYPE_URI_REFERENCE, DirectiveSet::TYPE_REPORTING_GROUP], true)) {
                $children->scalarNode($name)
                    ->end();
            } else {
                $children->arrayNode($name)
                    ->scalarPrototype()
                    ->end();
            }
        }

        return $children->end();
    }

    private function addReferrerPolicyNode(): ArrayNodeDefinition
    {
        $builder = new TreeBuilder('referrer_policy');
        $node = $builder->getRootNode();

        $node
            ->canBeEnabled()
            ->children()
                ->arrayNode('policies')
                    ->scalarPrototype()->end()
                    ->defaultValue(['no-referrer', 'no-referrer-when-downgrade'])
                    ->beforeNormalization()
                        ->ifString()
                        ->then(static function (string $value): array { return [$value]; })
                    ->end()
                    ->validate()
                        ->always(function (array $values): array {
                            foreach ($values as $policy) {
                                if (!\in_array($policy, $this->referrerPolicies, true)) {
                                    throw new \InvalidArgumentException(\sprintf('Unknown referrer policy "%s". Possible referrer policies are "%s".', $policy, implode('", "', $this->referrerPolicies)));
                                }
                            }

                            return $values;
                        })
                    ->end()
                ->end()
           ->end();

        return $node;
    }

    private function getSignedCookiesNode(): ArrayNodeDefinition
    {
        $node = new ArrayNodeDefinition('signed_cookie');
        $node
            ->fixXmlConfig('name')
            ->children()
                ->arrayNode('names')
                    ->scalarPrototype()->end()
                    ->defaultValue(['*'])
                ->end()
                ->scalarNode('secret')->defaultValue('%kernel.secret%')->end()
                ->scalarNode('hash_algo')->end()
                ->scalarNode('legacy_hash_algo')
                    ->defaultNull()
                    ->info('Fallback algorithm to allow for frictionless hash algorithm upgrades. Use with caution and as a temporary measure as it allows for downgrade attacks.')
                ->end()
                ->scalarNode('separator')->defaultValue('.')->end()
            ->end();

        return $node;
    }

    private function getClickjackingNode(): ArrayNodeDefinition
    {
        $node = new ArrayNodeDefinition('clickjacking');
        $node
            ->fixXmlConfig('path')
            ->children()
                ->arrayNode('hosts')
                    ->scalarPrototype()->end()
                    ->defaultValue([])
                ->end()
                ->arrayNode('paths')
                    ->normalizeKeys(false)
                    ->useAttributeAsKey('pattern')
                    ->arrayPrototype()
                        ->beforeNormalization()
                            ->always(static function ($v): array {
                                if (!\is_array($v)) {
                                    $v = ['header' => '' === $v ? 'DENY' : $v];
                                }
                                if (isset($v['header'])) {
                                    $v['header'] = preg_replace_callback('{^(?:ALLOW|DENY|SAMEORIGIN|ALLOW-FROM)?}i', static function ($m) { return strtoupper($m[0]); }, $v['header']);
                                }

                                return $v;
                            })
                            ->end()
                        ->validate()
                            ->ifTrue(static function (array $v): bool {
                                return isset($v['header']) && !\in_array($v['header'], ['DENY', 'SAMEORIGIN', 'ALLOW'], true)
                                    && 0 === preg_match('{^ALLOW-FROM \S+}', $v['header']);
                            })
                            ->thenInvalid('Possible header values are DENY, SAMEORIGIN, ALLOW and ALLOW-FROM [url], got: %s')
                        ->end()
                        ->children()
                            ->scalarNode('header')->defaultValue('DENY')->end()
                        ->end()
                    ->end()
                    ->defaultValue(['^/.*' => ['header' => 'DENY']])
                ->end()
            ->arrayNode('content_types')->scalarPrototype()->end()->defaultValue([])->end()
            ->end();

        return $node;
    }

    private function getExternalRedirectsNode(): ArrayNodeDefinition
    {
        $node = new ArrayNodeDefinition('external_redirects');
        $node
            ->validate()
                ->ifTrue(static function (array $v): bool {
                    return isset($v['abort'], $v['override']) && $v['abort'] && $v['override'];
                })
                ->thenInvalid('"abort" and "override" can not be combined')
            ->end()
            ->children()
                ->booleanNode('abort')->defaultFalse()->end()
                ->scalarNode('override')->defaultNull()->end()
                ->scalarNode('forward_as')->defaultNull()->end()
                ->booleanNode('log')->defaultFalse()->end()
                ->arrayNode('allow_list')
                    ->scalarPrototype()->end()
                ->end()
            ->end();

        return $node;
    }

    private function getXssProtectionNode(): ArrayNodeDefinition
    {
        $node = new ArrayNodeDefinition('xss_protection');
        $node->setDeprecated('nelmio/security-bundle', '3.4.0', 'The "%node%" option is deprecated, use Content Security Policy without allowing "unsafe-inline" scripts instead.');
        $node
            ->children()
                ->booleanNode('enabled')->defaultFalse()->end()
                ->booleanNode('mode_block')->defaultFalse()->end()
                ->scalarNode('report_uri')->defaultNull()->end()
            ->end();

        return $node;
    }

    private function getContentTypeNode(): ArrayNodeDefinition
    {
        $node = new ArrayNodeDefinition('content_type');
        $node
            ->children()
                ->booleanNode('nosniff')->defaultFalse()->end()
            ->end();

        return $node;
    }

    private function getForcedSslNode(): ArrayNodeDefinition
    {
        $node = new ArrayNodeDefinition('forced_ssl');
        $node
            ->canBeEnabled()
            ->children()
                ->scalarNode('hsts_max_age')->defaultNull()->end()
                ->booleanNode('hsts_subdomains')->defaultFalse()->end()
                ->booleanNode('hsts_preload')->defaultFalse()->end()
                ->arrayNode('allow_list')
                    ->scalarPrototype()->end()
                    ->defaultValue([])
                ->end()
                ->arrayNode('hosts')
                    ->scalarPrototype()->end()
                    ->defaultValue([])
                ->end()
            ->scalarNode('redirect_status_code')->defaultValue(302)->end()
            ->end();

        return $node;
    }

    private function getFlexibleSslNode(): ArrayNodeDefinition
    {
        $node = new ArrayNodeDefinition('flexible_ssl');
        $node
            ->canBeEnabled()
            ->children()
                ->scalarNode('cookie_name')->defaultValue('auth')->end()
                ->booleanNode('unsecured_logout')->defaultFalse()->end()
            ->end();

        return $node;
    }

    private function addPermissionsPolicyNode(): ArrayNodeDefinition
    {
        $node = new ArrayNodeDefinition('permissions_policy');

        $node->canBeEnabled();
        $policiesNode = $node
            ->children()
                ->arrayNode('policies')
                    ->children();

        foreach (Mapping::all() as $directive => $values) {
            $configKey = str_replace('-', '_', $directive);

            $policiesNode
                ->variableNode($configKey)
                    ->defaultNull()
                    ->validate()
                        ->ifTrue(static function ($values): bool {
                            if (null === $values || 'default' === $values || (\is_array($values) && [] === $values)) {
                                return false;
                            }

                            foreach ($values as $value) {
                                if (\in_array($value, Mapping::ALLOWED_VALUES, true)) {
                                    return false;
                                }

                                if (0 !== preg_match('/^https?:\/\//', $value)) {
                                    return false;
                                }
                            }

                            return true;
                        })
                        ->thenInvalid('Possible header values are *, self, src or a valid url starting with https:// got: %s')
                    ->end()
                ->end();
        }

        return $policiesNode
            ->end()
            ->end()
            ->end();
    }
}
