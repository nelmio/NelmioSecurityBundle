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
                        ->scalarNode('forward_as')->defaultNull()->end()
                        ->booleanNode('log')->defaultFalse()->end()
                        ->arrayNode('whitelist')
                            ->prototype('scalar')->end()
                        ->end()
                    ->end()
                ->end()

                ->arrayNode('flexible_ssl')
                    ->children()
                        ->booleanNode('enabled')->defaultTrue()->end()
                        ->scalarNode('cookie_name')->defaultValue('auth')->end()
                        ->booleanNode('unsecured_logout')->defaultFalse()->end()
                    ->end()
                ->end()

                ->arrayNode('forced_ssl')
                    ->children()
                        ->booleanNode('enabled')->defaultTrue()->end()
                        ->scalarNode('hsts_max_age')->defaultNull()->end()
                        ->booleanNode('hsts_subdomains')->defaultFalse()->end()
                        ->arrayNode('whitelist')
                            ->prototype('scalar')->end()
                        ->end()
                    ->end()
                ->end()

                ->arrayNode('cookie_session')
                    ->children()
                        ->booleanNode('enabled')->defaultTrue()->end()
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

                ->arrayNode('csp')
                    ->children()
                        ->arrayNode('default')
                            ->prototype('scalar')->end()
                            ->defaultValue(array())
                        ->end()
                        ->arrayNode('script')
                            ->prototype('scalar')->end()
                            ->defaultValue(array())
                        ->end()
                        ->arrayNode('object')
                            ->prototype('scalar')->end()
                            ->defaultValue(array())
                        ->end()
                        ->arrayNode('style')
                            ->prototype('scalar')->end()
                            ->defaultValue(array())
                        ->end()
                        ->arrayNode('img')
                            ->prototype('scalar')->end()
                            ->defaultValue(array())
                        ->end()
                        ->arrayNode('media')
                            ->prototype('scalar')->end()
                            ->defaultValue(array())
                        ->end()
                        ->arrayNode('frame')
                            ->prototype('scalar')->end()
                            ->defaultValue(array())
                        ->end()
                        ->arrayNode('font')
                            ->prototype('scalar')->end()
                            ->defaultValue(array())
                        ->end()
                        ->arrayNode('connect')
                            ->prototype('scalar')->end()
                            ->defaultValue(array())
                        ->end()
                        ->scalarNode('report_uri')->defaultValue('')->end()
                        ->booleanNode('report_only')->defaultValue(false)->end()
                    ->end()
                ->end()
            ->end()
        ->end();

        return $treeBuilder;
    }
}
