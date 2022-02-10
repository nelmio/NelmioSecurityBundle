<?php

/*
 * This file is part of the Nelmio SecurityBundle.
 *
 * (c) Nelmio <hello@nelm.io>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Nelmio\SecurityBundle\Tests\DependencyInjection;

use Nelmio\SecurityBundle\DependencyInjection\NelmioSecurityExtension;
use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\ContainerBuilder;

final class NelmioSecurityExtensionAllowListTest extends TestCase
{
    private $extension;

    protected function setUp()
    {
        $this->extension = new NelmioSecurityExtension();
    }

    /**
     * @group legacy
     */
    public function testLoadExternalRedirectWithDeprecatedWhiteList()
    {
        $container = new ContainerBuilder();

        $this->extension->load([
            [
                'external_redirects' => [
                    'whitelist' => ['twitter.com', 'https://www.facebook.com'],
                ],
            ],
        ], $container);

        $this->assertContainerWithParameterValue($container, 'nelmio_security.external_redirects.whitelist', '(?:.*\.twitter\.com|.*\.www\.facebook\.com|twitter\.com|www\.facebook\.com)');
    }

    public function testLoadExternalRedirectWithAllowList()
    {
        $container = new ContainerBuilder();
        $this->extension->load([
            [
                'external_redirects' => [
                    'allow_list' => ['twitter.com', 'https://www.facebook.com'],
                ],
            ],
        ], $container);

        $this->assertContainerWithParameterValue($container, 'nelmio_security.external_redirects.whitelist', '(?:.*\.twitter\.com|.*\.www\.facebook\.com|twitter\.com|www\.facebook\.com)');
    }

    public function testItFailsToLoadExternalRedirectWithAllowListAndWhiteList()
    {
        $container = new ContainerBuilder();

        $this->expectException(\LogicException::class);

        $this->extension->load([
            [
                'external_redirects' => [
                    'allow_list' => ['twitter.com', 'https://www.facebook.com'],
                    'whitelist' => ['twitter.com', 'https://www.facebook.com'],
                ],
            ],
        ], $container);
    }

    /**
     * @group legacy
     */
    public function testLoadForcedSslWithDeprecatedWhitelist()
    {
        $container = new ContainerBuilder();

        $this->extension->load([
            [
                'forced_ssl' => [
                    'whitelist' => ['^/unsecure/'],
                ],
            ],
        ], $container);

        $this->assertContainerWithParameterValue($container, 'nelmio_security.forced_ssl.whitelist', ['^/unsecure/']);
    }

    public function testLoadForcedSslWithAllowList()
    {
        $container = new ContainerBuilder();
        $this->extension->load([
            [
                'forced_ssl' => [
                    'allow_list' => ['^/unsecure/'],
                ],
            ],
        ], $container);

        $this->assertContainerWithParameterValue($container, 'nelmio_security.forced_ssl.whitelist', ['^/unsecure/']);
    }

    public function testItFailsToLoadForcedSslWithAllowListAndWhitelist()
    {
        $container = new ContainerBuilder();

        $this->expectException(\LogicException::class);

        $this->extension->load([
            [
                'forced_ssl' => [
                    'whitelist' => ['^/unsecure/'],
                    'allow_list' => ['^/unsecure/'],
                ],
            ],
        ], $container);

        $this->assertContainerWithParameterValue($container, 'nelmio_security.forced_ssl.whitelist', ['^/unsecure/']);
    }

    /**
     * @param mixed $value
     */
    private function assertContainerWithParameterValue(ContainerBuilder $container, $parameterName, $value)
    {
        $this->assertSame($value, $container->getParameter($parameterName));
    }
}
