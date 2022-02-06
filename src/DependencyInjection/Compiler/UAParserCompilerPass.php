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

namespace Nelmio\SecurityBundle\DependencyInjection\Compiler;

use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;

/**
 * @internal
 */
final class UAParserCompilerPass implements CompilerPassInterface
{
    public function process(ContainerBuilder $container): void
    {
        if (!$container->hasParameter('nelmio_browser_adaptive_parser')) {
            return;
        }

        $browserAdaptativeParser = $container->getParameter('nelmio_browser_adaptive_parser');

        \assert(\is_string($browserAdaptativeParser));

        $container
            ->getDefinition('nelmio_security.ua_parser')
            ->setArguments([new Reference($browserAdaptativeParser)]);
    }
}
