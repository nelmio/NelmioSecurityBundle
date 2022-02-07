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

use Nelmio\SecurityBundle\EventListener\ExternalRedirectListener;
use Nelmio\SecurityBundle\ExternalRedirect\AllowListBasedTargetValidator;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\DependencyInjection\Loader\Configurator\ReferenceConfigurator;

return static function (ContainerConfigurator $containerConfigurator): void {
    $containerConfigurator->parameters()
        ->set('nelmio_security.external_redirects.allow_list', null);

    $containerConfigurator->services()
        ->set('nelmio_security.external_redirect_listener', ExternalRedirectListener::class)
            ->args([
                '%nelmio_security.external_redirects.abort%',
                '%nelmio_security.external_redirects.override%',
                '%nelmio_security.external_redirects.forward_as%',
                (new ReferenceConfigurator('nelmio_security.external_redirect.target_validator'))->nullOnInvalid(),
                (new ReferenceConfigurator('logger'))->nullOnInvalid(),
                (new ReferenceConfigurator('router'))->nullOnInvalid(),
            ])
            ->tag('kernel.event_listener', [
                'event' => 'kernel.response',
                'method' => 'onKernelResponse',
            ])
            ->tag('monolog.logger', ['channel' => 'security'])

        ->alias('nelmio_security.external_redirect.target_validator', 'nelmio_security.external_redirect.target_validator.allow_list')

        ->set('nelmio_security.external_redirect.target_validator.allow_list', AllowListBasedTargetValidator::class)
            ->args([
                '%nelmio_security.external_redirects.allow_list%',
            ]);
};
