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
final class CspReportFilterCompilerPass implements CompilerPassInterface
{
    public function process(ContainerBuilder $container): void
    {
        if (!$container->hasDefinition('nelmio_security.csp_report.filter')) {
            return;
        }

        $services = $container->findTaggedServiceIds('nelmio_security.csp_report_filter');

        $cspViolationLogFilterDefinition = $container->getDefinition('nelmio_security.csp_report.filter');

        foreach ($services as $id => $attributes) {
            $cspViolationLogFilterDefinition->addMethodCall('addNoiseDetector', [new Reference($id)]);
        }
    }
}
