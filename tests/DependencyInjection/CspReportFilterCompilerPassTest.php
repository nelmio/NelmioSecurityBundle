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

namespace Nelmio\SecurityBundle\Tests\DependencyInjection;

use Nelmio\SecurityBundle\ContentSecurityPolicy\Violation\Filter\CustomRulesNoiseDetector;
use Nelmio\SecurityBundle\ContentSecurityPolicy\Violation\Filter\Filter;
use Nelmio\SecurityBundle\DependencyInjection\Compiler\CspReportFilterCompilerPass;
use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;

class CspReportFilterCompilerPassTest extends TestCase
{
    public function testNoExceptionIsThrownWhenCspReportFilterServiceDoesNotExist(): void
    {
        $builder = new ContainerBuilder();

        $compilerPass = new CspReportFilterCompilerPass();
        $compilerPass->process($builder);

        $this->assertFalse($builder->has('nelmio_security.csp_report.filter'));
    }

    public function testAddMethodCallsToCspReportFilter(): void
    {
        $builder = new ContainerBuilder();

        $noiseDetectorDefinition = new Definition(
            CustomRulesNoiseDetector::class
        );
        $noiseDetectorDefinition->addTag('nelmio_security.csp_report_filter');

        $builder->addDefinitions([
            'nelmio_security.csp_report.filter' => new Definition(
                Filter::class
            ),
            'nelmio_security.noise_detector' => $noiseDetectorDefinition,
        ]);

        $compilerPass = new CspReportFilterCompilerPass();
        $compilerPass->process($builder);

        $methodCalls = $builder->getDefinition('nelmio_security.csp_report.filter')->getMethodCalls();

        $this->assertCount(1, $methodCalls);

        $this->assertSame('addNoiseDetector', $methodCalls[0][0]);
        $this->assertSame('nelmio_security.noise_detector', (string) $methodCalls[0][1][0]);
    }
}
