<?php

/*
 * This file is part of the Nelmio SecurityBundle.
 *
 * (c) Nelmio <hello@nelm.io>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Nelmio\SecurityBundle;

use Nelmio\SecurityBundle\ContentSecurityPolicy\Violation\Events;
use Nelmio\SecurityBundle\ContentSecurityPolicy\Violation\ReportEvent;
use Nelmio\SecurityBundle\DependencyInjection\Compiler\CspReportFilterCompilerPass;
use Nelmio\SecurityBundle\DependencyInjection\Compiler\UAParserCompilerPass;
use Symfony\Component\EventDispatcher\DependencyInjection\AddEventAliasesPass;
use Symfony\Component\HttpKernel\Bundle\Bundle;
use Symfony\Component\DependencyInjection\ContainerBuilder;

class NelmioSecurityBundle extends Bundle
{
    public function build(ContainerBuilder $container)
    {
        parent::build($container);

        $container->addCompilerPass(new UAParserCompilerPass());
        $container->addCompilerPass(new CspReportFilterCompilerPass());

        if (class_exists(AddEventAliasesPass::class)) {
            $container->addCompilerPass(new AddEventAliasesPass([
                ReportEvent::class => Events::VIOLATION_REPORT,
            ]));
        }
    }
}
