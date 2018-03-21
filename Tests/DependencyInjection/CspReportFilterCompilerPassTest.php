<?php

namespace Nelmio\Tests\SecurityBundle\DependencyInjection\Compiler;

use Nelmio\SecurityBundle\DependencyInjection\Compiler\CspReportFilterCompilerPass;
use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Reference;

class CspReportFilterCompilerPassTest extends TestCase
{
    public function testNoExceptionIsThrownWhenCspReportFilterServiceDoesNotExist()
    {
        $builder = new ContainerBuilder();

        $compilerPass = new CspReportFilterCompilerPass();
        $compilerPass->process($builder);

        $this->assertFalse($builder->has('nelmio_security.csp_report.filter'));
    }

    public function testAddMethodCallsToCspReportFilter()
    {
        $builder = new ContainerBuilder();

        $noiseDetectorDefinition = new Definition(
            'Nelmio\SecurityBundle\ContentSecurityPolicy\Violation\Filter\CustomRulesNoiseDetector'
        );
        $noiseDetectorDefinition->addTag('nelmio_security.csp_report_filter');

        $builder->addDefinitions(array(
            'nelmio_security.csp_report.filter' => new Definition(
                'Nelmio\SecurityBundle\ContentSecurityPolicy\Violation\Filter\Filter'
            ),
            'nelmio_security.noise_detector' => $noiseDetectorDefinition
        ));

        $compilerPass = new CspReportFilterCompilerPass();
        $compilerPass->process($builder);

        $methodCalls = $builder->getDefinition('nelmio_security.csp_report.filter')->getMethodCalls();

        $this->assertCount(1, $methodCalls);

        $this->assertEquals('addNoiseDetector', $methodCalls[0][0]);
        $this->assertEquals(new Reference('nelmio_security.noise_detector'), $methodCalls[0][1][0]);
    }
}
