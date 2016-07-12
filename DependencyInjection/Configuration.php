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

use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;
use Nelmio\SecurityBundle\ContentSecurityPolicy\DirectiveSet;

class Configuration implements ConfigurationInterface
{
    public function getConfigTreeBuilder()
    {
        $treeBuilder = new TreeBuilder();
        $rootNode = $treeBuilder->root('nelmio_security', 'array');

        $rootNode
            ->validate()
                ->ifTrue(function ($v) {
                    return $v['forced_ssl']['enabled'] && $v['flexible_ssl']['enabled'];
                })
                ->thenInvalid('"forced_ssl" and "flexible_ssl" can not be used together')
            ->end()
            ->children()
                ->arrayNode('signed_cookie')
                    ->fixXmlConfig('name')
                    ->children()
                        ->arrayNode('names')
                            ->prototype('scalar')->end()
                            ->defaultValue(array('*'))
                        ->end()
                        ->scalarNode('secret')->defaultValue('%kernel.secret%')->end()
                        ->scalarNode('hash_algo')->defaultValue('sha256')->end()
                    ->end()
                ->end()

                ->arrayNode('encrypted_cookie')
                    ->fixXmlConfig('name')
                    ->children()
                        ->arrayNode('names')
                            ->prototype('scalar')->end()
                            ->defaultValue(array('*'))
                        ->end()
                        ->scalarNode('secret')->defaultValue('%kernel.secret%')->end()
                        ->scalarNode('algorithm')->defaultValue('rijndael-128')->end()
                    ->end()
                ->end()

                ->arrayNode('clickjacking')
                    ->fixXmlConfig('path')
                    ->children()
                        ->arrayNode('paths')
                            ->normalizeKeys(false)
                            ->useAttributeAsKey('pattern')
                            ->prototype('array')
                                ->beforeNormalization()
                                    ->always(function ($v) {
                                        if (!is_array($v)) {
                                            $v = array('header' => $v ?: 'DENY');
                                        }
                                        if (isset($v['header'])) {
                                            $v['header'] = preg_replace_callback('{^(?:ALLOW|DENY|SAMEORIGIN|ALLOW-FROM)?}i', function ($m) { return strtoupper($m[0]); }, $v['header']);
                                        }

                                        return $v;
                                    })
                                ->end()
                                ->validate()
                                    ->ifTrue(function ($v) {
                                        return isset($v['header']) && !in_array($v['header'], array('DENY', 'SAMEORIGIN', 'ALLOW'), true)
                                            && !preg_match('{^ALLOW-FROM \S+}', $v['header']);
                                    })
                                    ->thenInvalid('Possible header values are DENY, SAMEORIGIN, ALLOW and ALLOW-FROM [url], got: %s')
                                ->end()
                                ->children()
                                    ->scalarNode('header')->defaultValue('DENY')->end()
                                ->end()
                            ->end()
                            ->defaultValue(array('^/.*' => array('header' => 'DENY')))
                        ->end()
                        ->arrayNode('content_types')->prototype('scalar')->end()->defaultValue(array())->end()
                    ->end()
                ->end()

                ->arrayNode('external_redirects')
                    ->validate()
                        ->ifTrue(function ($v) {
                            return isset($v['abort']) && $v['abort'] && isset($v['override']) && $v['override'];
                        })
                        ->thenInvalid('"abort" and "override" can not be combined')
                    ->end()
                    ->children()
                        ->booleanNode('abort')->defaultFalse()->end()
                        ->scalarNode('override')->defaultNull()->end()
                        ->scalarNode('forward_as')->defaultNull()->end()
                        ->booleanNode('log')->defaultFalse()->end()
                        ->arrayNode('whitelist')
                            ->prototype('scalar')->end()
                        ->end()
                    ->end()
                ->end()

                ->arrayNode('flexible_ssl')
                    ->canBeEnabled()
                    ->children()
                        ->scalarNode('cookie_name')->defaultValue('auth')->end()
                        ->booleanNode('unsecured_logout')->defaultFalse()->end()
                    ->end()
                ->end()

                ->arrayNode('forced_ssl')
                    ->canBeEnabled()
                    ->children()
                        ->scalarNode('hsts_max_age')->defaultNull()->end()
                        ->booleanNode('hsts_subdomains')->defaultFalse()->end()
                        ->booleanNode('hsts_preload')->defaultFalse()->end()
                        ->arrayNode('whitelist')
                            ->prototype('scalar')->end()
                            ->defaultValue(array())
                        ->end()
                        ->arrayNode('hosts')
                            ->prototype('scalar')->end()
                            ->defaultValue(array())
                        ->end()
                    ->end()
                ->end()

                ->arrayNode('cookie_session')
                    ->canBeEnabled()
                    ->children()
                        ->scalarNode('name')->defaultValue('session')->end()
                        ->scalarNode('lifetime')->defaultValue(0)->end()
                        ->scalarNode('path')->defaultValue('/')->end()
                        ->scalarNode('domain')->defaultNull()->end()
                        ->booleanNode('secure')->defaultFalse()->end()
                        ->booleanNode('httponly')->defaultTrue()->end()
                    ->end()
                ->end()

                ->arrayNode('content_type')
                    ->children()
                        ->booleanNode('nosniff')->defaultFalse()->end()
                    ->end()
                ->end()

                ->arrayNode('xss_protection')
                    ->children()
                        ->booleanNode('enabled')->defaultFalse()->end()
                        ->booleanNode('mode_block')->defaultFalse()->end()
                    ->end()
                ->end()

                ->append($this->addCspNode())
            ->end()
        ->end();

        return $treeBuilder;
    }

    private function addCspNode()
    {
        $builder = new TreeBuilder();
        $node = $builder->root('csp');

        $node
            ->children()
                ->arrayNode('hosts')->prototype('scalar')->end()->defaultValue(array())->end()
                ->arrayNode('content_types')->prototype('scalar')->end()->defaultValue(array())->end()
                // leaving this enabled can cause issues with older iOS (5.x) versions
                // and possibly other early CSP implementations
                ->booleanNode('compat_headers')->defaultValue(true)->end()
                ->scalarNode('report_logger_service')->defaultValue('logger')->end()
                ->arrayNode('hash')
                    ->addDefaultsIfNotSet()
                    ->children()
                        ->enumNode('algorithm')
                            ->info('The algorithm to use for hashes')
                            ->values(array('sha256', 'sha384', 'sha512'))
                            ->defaultValue('sha256')
                        ->end()
                    ->end()
                ->end()
                ->append($this->addReportOrEnforceNode('report'))
                ->append($this->addReportOrEnforceNode('enforce'))
            ->end();

        return $node;
    }

    private function addReportOrEnforceNode($reportOrEnforce)
    {
        $builder = new TreeBuilder();
        $node = $builder->root($reportOrEnforce);
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
                ->beforeNormalization()
                    ->always(function ($v) {
                        if (!is_array($v)) {
                            @trigger_error("browser_adaptive configuration is now an array. Using boolean is deprecated and will not be supported anymore in version 3", E_USER_DEPRECATED);

                            return array(
                                'enabled' => $v,
                                'parser' => 'nelmio_security.ua_parser.ua_php',
                            );
                        }

                        return $v;
                    })
                ->end()
            ->end();

        foreach (DirectiveSet::getNames() as $name => $type) {
            if (DirectiveSet::TYPE_NO_VALUE === $type) {
                $children
                    ->booleanNode($name)
                    ->defaultFalse()
                    ->end();
            } elseif ($name === 'report-uri') {
                $children
                    ->arrayNode($name)
                        ->prototype('scalar')->end()
                        ->beforeNormalization()
                            ->ifString()
                            ->then(function ($value) { return array($value); })
                        ->end()
                    ->end();
            } elseif (DirectiveSet::TYPE_URI_REFERENCE === $type) {
                $children->scalarNode($name)
                    ->end();
            } else {
                $children->arrayNode($name)
                    ->prototype('scalar')
                    ->end();
            }
        }

        return $children->end();
    }
}
