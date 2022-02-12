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

use Nelmio\SecurityBundle\DependencyInjection\NelmioSecurityExtension;
use Nelmio\SecurityBundle\EventListener\ClickjackingListener;
use Nelmio\SecurityBundle\EventListener\ExternalRedirectListener;
use Nelmio\SecurityBundle\EventListener\FlexibleSslListener;
use Nelmio\SecurityBundle\EventListener\ForcedSslListener;
use Nelmio\SecurityBundle\EventListener\SignedCookieListener;
use Nelmio\SecurityBundle\ExternalRedirect\WhitelistBasedTargetValidator;
use Nelmio\SecurityBundle\Signer;
use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\ContainerBuilder;

final class NelmioSecurityExtensionTest extends TestCase
{
    private NelmioSecurityExtension $extension;

    protected function setUp(): void
    {
        $this->extension = new NelmioSecurityExtension();
    }

    public function testLoadSignedCookie(): void
    {
        $container = new ContainerBuilder();
        $this->extension->load([
            [
                'signed_cookie' => [
                    'names' => ['name1', 'name2'],
                    'secret' => 's3cr3t',
                    'hash_algo' => 'hash',
                ],
            ],
        ], $container);

        $this->assertContainerWithParameterValue($container, 'nelmio_security.signed_cookie.names', ['name1', 'name2']);
        $this->assertContainerWithParameterValue($container, 'nelmio_security.signer.secret', 's3cr3t');
        $this->assertContainerWithParameterValue($container, 'nelmio_security.signer.hash_algo', 'hash');

        $this->assertServiceIdClass($container, 'nelmio_security.signed_cookie_listener', SignedCookieListener::class);
        $this->assertServiceIdClass($container, 'nelmio_security.signer', Signer::class);
    }

    public function testLoadClickJacking(): void
    {
        $container = new ContainerBuilder();
        $this->extension->load([
            [
                'clickjacking' => [
                    'paths' => ['^/frames/' => ['header' => 'ALLOW']],
                    'content_types' => ['text/html'],
                ],
            ],
        ], $container);

        $this->assertContainerWithParameterValue($container, 'nelmio_security.clickjacking.paths', ['^/frames/' => ['header' => 'ALLOW']]);
        $this->assertContainerWithParameterValue($container, 'nelmio_security.clickjacking.content_types', ['text/html']);

        $this->assertServiceIdClass($container, 'nelmio_security.clickjacking_listener', ClickjackingListener::class);
    }

    public function testFlexibleSsl(): void
    {
        $container = new ContainerBuilder();
        $this->extension->load([
            [
                'flexible_ssl' => [
                    'cookie_name' => 'auth',
                    'unsecured_logout' => false,
                ],
            ],
        ], $container);

        $this->assertContainerWithParameterValue($container, 'nelmio_security.flexible_ssl.cookie_name', 'auth');
        $this->assertContainerWithParameterValue($container, 'nelmio_security.flexible_ssl.unsecured_logout', false);

        $this->assertServiceIdClass($container, 'nelmio_security.flexible_ssl_listener', FlexibleSslListener::class);
    }

    public function testLoadExternalRedirect(): void
    {
        $container = new ContainerBuilder();
        $this->extension->load([
            [
                'external_redirects' => [
                    'abort' => true,
                    'allow_list' => ['twitter.com', 'https://www.facebook.com'],
                ],
            ],
        ], $container);

        $this->assertContainerWithParameterValue($container, 'nelmio_security.external_redirects.override', null);
        $this->assertContainerWithParameterValue($container, 'nelmio_security.external_redirects.abort', true);
        $this->assertContainerWithParameterValue($container, 'nelmio_security.external_redirects.forward_as', null);
        $this->assertContainerWithParameterValue($container, 'nelmio_security.external_redirects.whitelist', '(?:.*\.twitter\.com|.*\.www\.facebook\.com|twitter\.com|www\.facebook\.com)');

        $this->assertServiceIdClass($container, 'nelmio_security.external_redirect_listener', ExternalRedirectListener::class);
        $this->assertServiceIdClass($container, 'nelmio_security.external_redirect.target_validator.whitelist', WhitelistBasedTargetValidator::class);

        $this->assertTrue($container->hasAlias('nelmio_security.external_redirect.target_validator'));
        $this->assertSame('nelmio_security.external_redirect.target_validator.whitelist', (string) $container->getAlias('nelmio_security.external_redirect.target_validator'));
    }

    public function testLoadForcedSsl(): void
    {
        $container = new ContainerBuilder();
        $this->extension->load([
            [
                'forced_ssl' => [
                    'enabled' => true,
                    'allow_list' => ['^/unsecure/'],
                    'hosts' => ['^\.example\.org$'],
                    'redirect_status_code' => 301,
                    'hsts_max_age' => 2592000,
                    'hsts_subdomains' => true,
                ],
            ],
        ], $container);

        $this->assertContainerWithParameterValue($container, 'nelmio_security.forced_ssl.hsts_max_age', 2592000);
        $this->assertContainerWithParameterValue($container, 'nelmio_security.forced_ssl.hsts_subdomains', true);
        $this->assertContainerWithParameterValue($container, 'nelmio_security.forced_ssl.hsts_preload', false);
        $this->assertContainerWithParameterValue($container, 'nelmio_security.forced_ssl.whitelist', ['^/unsecure/']);
        $this->assertContainerWithParameterValue($container, 'nelmio_security.forced_ssl.hosts', ['^\.example\.org$']);

        $this->assertServiceIdClass($container, 'nelmio_security.forced_ssl_listener', ForcedSslListener::class);

        $listener = $container->findDefinition('nelmio_security.forced_ssl_listener');
        $this->assertCount(2, $listener->getTag('kernel.event_listener'));
    }

    private function assertServiceIdClass(ContainerBuilder $container, string $serviceId, string $className): void
    {
        $this->assertSame($className, $container->findDefinition($serviceId)->getClass());
    }

    /**
     * @param mixed $value
     */
    private function assertContainerWithParameterValue(ContainerBuilder $container, string $parameterName, $value): void
    {
        $this->assertSame($value, $container->getParameter($parameterName));
    }
}
