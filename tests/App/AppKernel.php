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
use Nelmio\SecurityBundle\Tests\App\Controller\ExternalRedirectAction;
use Symfony\Bundle\FrameworkBundle\Controller\TemplateController;
use Symfony\Bundle\FrameworkBundle\FrameworkBundle;
use Symfony\Bundle\FrameworkBundle\Kernel\MicroKernelTrait;
use Symfony\Bundle\TwigBundle\TwigBundle;
use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\HttpKernel\Kernel;
use Symfony\Component\Routing\Loader\Configurator\RoutingConfigurator;
use Symfony\Component\Routing\RouteCollectionBuilder;

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
     * Remove RouteCollectionBuilder when dropping support for Symfony < 5.4.
     *
     * @param RoutingConfigurator|RouteCollectionBuilder $routes
     */
    protected function configureRoutes($routes): void
    {
        if ($routes instanceof RouteCollectionBuilder) {
            $routes->add('/', TemplateController::class)
                ->addDefaults(['template' => 'homepage.html.twig']);

            $routes->add('/clickjacking/{action}', TemplateController::class)
                ->addDefaults(['template' => 'homepage.html.twig']);

            $routes->add('/external_redirect', ExternalRedirectAction::class);
        } else {
            $routes->add('home', '/')
                ->controller(TemplateController::class)
                ->defaults(['template' => 'homepage.html.twig'])
            ;

            $routes->add('clickjacking', '/clickjacking/{action}')
                ->controller(TemplateController::class)
                ->defaults(['template' => 'homepage.html.twig'])
            ;

            $routes->add('external_redirect', '/external_redirect')
                ->controller(ExternalRedirectAction::class)
            ;
        }
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
