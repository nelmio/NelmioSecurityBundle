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
use Symfony\Component\Config\Definition\Builder\NodeBuilder;
use Nelmio\SecurityBundle\ContentSecurityPolicy\DirectiveSet;

class Configuration implements ConfigurationInterface
{
    public function getConfigTreeBuilder()
    {
        $treeBuilder = new TreeBuilder();
        $rootNode = $treeBuilder->root('nelmio_security', 'array');

        $rootNode
            ->validate()
                ->ifTrue(function($v) {
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
                                    ->always(function($v) {
                                        if (!is_array($v)) {
                                            $v = array('header' => $v ?: 'DENY');
                                        }
                                        if (isset($v['header'])) {
                                            $v['header'] = preg_replace_callback('{^(?:ALLOW|DENY|SAMEORIGIN)(?: FROM)?}i', function ($m) { return strtoupper($m[0]); }, $v['header']);
                                        }

                                        return $v;
                                    })
                                ->end()
                                ->validate()
                                    ->ifTrue(function($v) {
                                        return isset($v['header']) && !in_array($v['header'], array('DENY', 'SAMEORIGIN', 'ALLOW'), true)
                                            && !preg_match('{^ALLOW FROM \S+}', $v['header']);
                                    })
                                    ->thenInvalid('Possible header values are DENY, SAMEORIGIN, ALLOW and ALLOW FROM [url], got: %s')
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

        $this
            ->addDirectives($node->children())
                ->scalarNode('report_uri')->defaultValue('')->end()
                ->booleanNode('report_only')->end()
                ->arrayNode('hosts')->prototype('scalar')->end()->defaultValue(array())->end()
                ->arrayNode('content_types')->prototype('scalar')->end()->defaultValue(array())->end()
                // leaving this enabled can cause issues with older iOS (5.x) versions
                // and possibly other early CSP implementations
                ->booleanNode('compat_headers')->defaultValue(true)->end()
                ->scalarNode('report_logger_service')->defaultValue('logger')->end()
                ->append($this->addReportOrEnforceNode('report'))
                ->append($this->addReportOrEnforceNode('enforce'))
            ->end()
            ->validate()
                ->ifTrue(function($v) {
                    return array_key_exists('report_only', $v)
                        && (array_key_exists('report', $v) || array_key_exists('enforce', $v));
                })
                ->thenInvalid('"report_only" and "(report|enforce)" can not be used together')
            ->end()
            ->validate()
                ->ifTrue(
                    function($v) {
                        return
                            !array_key_exists('report', $v)
                            && !array_key_exists('enforce', $v)
                            && !array_key_exists('report_only', $v);
                    }
                )
                ->then(function($c) {
                    $c['report_only'] = false;
                    return $c;
                })
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

        foreach (DirectiveSet::getNames() as $name) {
            $children
                ->arrayNode($name)
                ->prototype('scalar')
                ->end();
        }
        return $children->end();
    }

    private function addDirectives(NodeBuilder $node)
    {
        $directives = array(
            'default',
            'script',
            'object',
            'style',
            'img',
            'media',
            'frame',
            'font',
            'connect'
        );

        foreach ($directives as $directive) {
            $node
                ->arrayNode($directive)
                ->prototype('scalar')
                ->end();
        }

        return $node;
    }
}
