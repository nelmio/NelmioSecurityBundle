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

namespace Nelmio\SecurityBundle\Tests\App;

use Nelmio\SecurityBundle\NelmioSecurityBundle;
use Symfony\Bundle\FrameworkBundle\FrameworkBundle;
use Symfony\Bundle\FrameworkBundle\Kernel\MicroKernelTrait;
use Symfony\Bundle\TwigBundle\TwigBundle;
use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\HttpKernel\Kernel;
use Symfony\Component\Routing\Loader\Configurator\RoutingConfigurator;

class AppKernel extends Kernel
{
    use MicroKernelTrait;

    public function __construct()
    {
        parent::__construct('test', false);
    }

    public function registerBundles(): iterable
    {
        return [
            new FrameworkBundle(),
            new TwigBundle(),
            new NelmioSecurityBundle(),
        ];
    }

    /**
     * Add RoutingConfigurator type declaration when dropping support for Symfony < 5.4.
     *
     * @param RoutingConfigurator $routes
     */
    protected function configureRoutes($routes): void
    {
        $routes->import(sprintf('%s/config/routes.yaml', $this->getProjectDir()));
    }

    protected function configureContainer(ContainerBuilder $containerBuilder, LoaderInterface $loader): void
    {
        $loader->load(sprintf('%s/config/config.yaml', $this->getProjectDir()));
    }

    public function getCacheDir(): string
    {
        return sprintf('%scache', $this->getBaseDir());
    }

    public function getLogDir(): string
    {
        return sprintf('%slog', $this->getBaseDir());
    }

    public function getProjectDir(): string
    {
        return __DIR__;
    }

    private function getBaseDir(): string
    {
        return sprintf('%s/nelmio-security-bundle/var/', sys_get_temp_dir());
    }
}
