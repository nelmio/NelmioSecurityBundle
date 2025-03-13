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

namespace Nelmio\SecurityBundle\ContentSecurityPolicy;

class ConfigurationDirectiveSetBuilder implements DirectiveSetBuilderInterface
{
    private DirectiveSet $directiveSet;

    /**
     * @phpstan-param array{
     *      enforce?: array<string, mixed>,
     *      report?: array<string, mixed>,
     *  } $config
     * @phpstan-param 'enforce'|'report' $kind
     */
    public function __construct(PolicyManager $policyManager, array $config, string $kind)
    {
        $this->directiveSet = DirectiveSet::fromConfig($policyManager, $config, $kind);
    }

    public function buildDirectiveSet(): DirectiveSet
    {
        return $this->directiveSet;
    }

    /**
     * @phpstan-param array{
     *     enforce?: array<string, mixed>,
     *     report?: array<string, mixed>,
     * } $config
     * @phpstan-param 'enforce'|'report' $kind
     */
    public static function create(PolicyManager $policyManager, array $config, string $kind): self
    {
        return new self($policyManager, $config, $kind);
    }
}
