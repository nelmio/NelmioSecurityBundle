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

use Symfony\Component\Config\Definition\Builder\TreeBuilder,
    Symfony\Component\Config\Definition\ConfigurationInterface;

class Configuration implements ConfigurationInterface
{
    public function getConfigTreeBuilder()
    {
        $treeBuilder = new TreeBuilder();
        $rootNode = $treeBuilder->root('nelmio_security', 'array');

        $rootNode
            ->validate()
                ->ifTrue(function($v) {
                    return array_key_exists('forced_ssl', $v) && array_key_exists('flexible_ssl', $v);
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

                ->arrayNode('clickjacking')
                    ->fixXmlConfig('path')
                    ->children()
                        ->arrayNode('paths')
                            ->useAttributeAsKey('pattern')
                            ->prototype('array')
                                ->beforeNormalization()
                                    ->always(function($v) {
                                        if (!is_array($v)) {
                                            return array('header' => strtoupper($v ?: 'DENY'));
                                        }
                                        if (isset($v['header'])) {
                                            $v['header'] = strtoupper($v['header']);
                                        }
                                        return $v;
                                    })
                                ->end()
                                ->validate()
                                    ->ifTrue(function($v) {
                                        return isset($v['header']) && !in_array($v['header'], array('DENY', 'SAMEORIGIN', 'ALLOW'));
                                    })
                                    ->thenInvalid('Possible header values are DENY, SAMEORIGIN and ALLOW, got: %s')
                                ->end()
                                ->children()
                                    ->scalarNode('header')->defaultValue('DENY')->end()
                                ->end()
                            ->end()
                            ->defaultValue(array('^/.*' => array('header' => 'DENY')))
                        ->end()
                    ->end()
                ->end()

                ->arrayNode('external_redirects')
                    ->validate()
                        ->ifTrue(function($v) {
                            return isset($v['abort']) && $v['abort'] && isset($v['override']) && $v['override'];
                        })
                        ->thenInvalid('"abort" and "override" can not be combined')
                    ->end()
                    ->children()
                        ->booleanNode('abort')->defaultFalse()->end()
                        ->scalarNode('override')->defaultNull()->end()
                        ->booleanNode('log')->defaultFalse()->end()
                        ->arrayNode('whitelist')
                            ->prototype('scalar')->end()
                        ->end()
                    ->end()
                ->end()

                ->arrayNode('flexible_ssl')
                    ->children()
                        ->scalarNode('cookie_name')->defaultValue('auth')->end()
                    ->end()
                ->end()

                ->arrayNode('forced_ssl')
                    ->children()
                        ->scalarNode('hsts_max_age')->defaultNull()->end()
                        ->booleanNode('hsts_subdomains')->defaultFalse()->end()
                    ->end()
                ->end()
            ->end()
        ->end();

        return $treeBuilder;
    }
}
