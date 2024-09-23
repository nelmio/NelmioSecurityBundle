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

use Symfony\Component\HttpFoundation\Request;

final class DirectiveSet
{
    /** @internal */
    public const TYPE_SRC_LIST_NOFB = 'source-list-no-fallback';
    /** @internal */
    public const TYPE_MEDIA_TYPE_LIST = 'media-type-list';
    /** @internal */
    public const TYPE_ANCESTOR_SRC_LIST = 'ancestor-source-list';
    /** @internal */
    public const TYPE_URI_REFERENCE = 'uri-reference';
    /** @internal */
    public const TYPE_NO_VALUE = 'no-value';
    /** @internal */
    public const TYPE_SRC_LIST = 'source-list';
    /** @internal */
    public const TYPE_REPORTING_GROUP = 'reporting-group';

    /**
     * @var array<string, string>
     */
    private static array $directiveNames = [
        'default-src' => self::TYPE_SRC_LIST,
        'base-uri' => self::TYPE_SRC_LIST_NOFB,
        'block-all-mixed-content' => self::TYPE_NO_VALUE,
        'child-src' => self::TYPE_SRC_LIST,
        'connect-src' => self::TYPE_SRC_LIST,
        'font-src' => self::TYPE_SRC_LIST,
        'form-action' => self::TYPE_SRC_LIST_NOFB,
        'frame-ancestors' => self::TYPE_ANCESTOR_SRC_LIST,
        'frame-src' => self::TYPE_SRC_LIST,
        'img-src' => self::TYPE_SRC_LIST,
        'manifest-src' => self::TYPE_SRC_LIST,
        'media-src' => self::TYPE_SRC_LIST,
        'object-src' => self::TYPE_SRC_LIST,
        'plugin-types' => self::TYPE_MEDIA_TYPE_LIST,
        'script-src' => self::TYPE_SRC_LIST,
        'style-src' => self::TYPE_SRC_LIST,
        'upgrade-insecure-requests' => self::TYPE_NO_VALUE,
        'report-uri' => self::TYPE_URI_REFERENCE,
        'worker-src' => self::TYPE_SRC_LIST,
        'prefetch-src' => self::TYPE_SRC_LIST,
        'report-to' => self::TYPE_REPORTING_GROUP,
    ];

    /**
     * @var array<string, string|true>
     */
    private array $directiveValues = [];
    private bool $level1Fallback = true;
    private PolicyManager $policyManager;

    public function __construct(PolicyManager $policyManager)
    {
        $this->policyManager = $policyManager;
    }

    public function setLevel1Fallback(bool $bool): void
    {
        $this->level1Fallback = $bool;
    }

    /**
     * @return string|true
     */
    public function getDirective(string $name)
    {
        $this->checkDirectiveName($name);

        if (\array_key_exists($name, $this->directiveValues)) {
            return $this->directiveValues[$name];
        }

        return '';
    }

    /**
     * @param string|true $value
     */
    public function setDirective(string $name, $value): void
    {
        $this->checkDirectiveName($name);
        if (self::TYPE_NO_VALUE === self::$directiveNames[$name]) {
            if (true === $value) {
                $this->directiveValues[$name] = true;
            } else {
                unset($this->directiveValues[$name]);
            }
        } elseif ('' !== $value) {
            $this->directiveValues[$name] = $value;
        } else {
            unset($this->directiveValues[$name]);
        }
    }

    /**
     * @param array<string, string|true> $directives
     */
    public function setDirectives(array $directives): void
    {
        foreach ($directives as $name => $value) {
            $this->setDirective($name, $value);
        }
    }

    /**
     * @param array<string, list<string>>|null $signatures
     */
    public function buildHeaderValue(Request $request, ?array $signatures = null): string
    {
        $policy = [];

        $signatures = $this->normalizeSignatures($signatures);

        $availableDirectives = $this->policyManager->getAvailableDirective($request);

        foreach ($this->directiveValues as $name => $value) {
            if (!\in_array($name, $availableDirectives, true)) {
                continue;
            }
            if (true === $value) {
                $policy[] = $name;
            } elseif (isset($signatures[$name])) {
                // since a hash / nonce is used (CSP level2)
                // In case the browsers support CSP level 2, it would discard the 'unsafe-inline' directive
                // let's ensure that it's backward compatible with CSP level 1 (all browsers are not compatible)
                // this is the recommended way to deal with this.
                if (false === strpos($value, '\'unsafe-inline\'') && $this->level1Fallback) {
                    $policy[] = $name.' '.$value.' \'unsafe-inline\' '.$signatures[$name];
                } else {
                    $policy[] = $name.' '.$value.' '.$signatures[$name];
                }
            } elseif ($this->canNotBeFallbackedByDefault($name, $value)) {
                $policy[] = $name.' '.$value;
            }
        }

        if (null !== $signatures && [] !== $signatures) {
            $defaultSrc = $this->getDirective('default-src');
            $isDefaultSrcSet = '' !== $defaultSrc && true !== $defaultSrc;

            if ($isDefaultSrcSet && false === strpos($defaultSrc, '\'unsafe-inline\'')) {
                $unsafeInline = $this->level1Fallback ? ' \'unsafe-inline\'' : '';

                if (!isset($this->directiveValues['script-src']) && isset($signatures['script-src'])) {
                    $policy[] = 'script-src '.$defaultSrc.$unsafeInline.' '.$signatures['script-src'];
                }

                if (!isset($this->directiveValues['style-src']) && isset($signatures['style-src'])) {
                    $policy[] = 'style-src '.$defaultSrc.$unsafeInline.' '.$signatures['style-src'];
                }
            }
        }

        return implode('; ', $policy);
    }

    /**
     * @phpstan-param array{
     *     enforce?: array<string, mixed>,
     *     report?: array<string, mixed>,
     * } $config
     * @phpstan-param 'enforce'|'report' $kind
     */
    public static function fromConfig(PolicyManager $policyManager, array $config, string $kind): self
    {
        $directiveSet = new self($policyManager);
        $directiveSet->setLevel1Fallback(isset($config[$kind]) ? $config[$kind]['level1_fallback'] : false);

        if (!\array_key_exists($kind, $config)) {
            return $directiveSet;
        }

        $parser = new ContentSecurityPolicyParser();
        foreach (self::getNames() as $name => $type) {
            if (!\array_key_exists($name, $config[$kind])) {
                continue;
            }

            $directiveSet->setDirective($name, $parser->parseSourceList($config[$kind][$name]));
        }

        return $directiveSet;
    }

    /**
     * @return array<string, string>
     */
    public static function getNames(): array
    {
        return self::$directiveNames;
    }

    private function checkDirectiveName(string $name): void
    {
        if (!\array_key_exists($name, self::$directiveNames)) {
            throw new \InvalidArgumentException('Unknown CSP directive name: '.$name);
        }
    }

    private function canNotBeFallbackedByDefault(string $name, string $value): bool
    {
        if ('default-src' === $name) {
            return true;
        }

        // Only source-list can be fallbacked by default
        if (self::TYPE_SRC_LIST !== self::$directiveNames[$name]) {
            return true;
        }

        // let's fallback if directives are strictly equals
        return $value !== $this->getDirective('default-src');
    }

    /**
     * @param array<string, list<string>>|null $signatures
     *
     * @return array<string, string>|null
     */
    private function normalizeSignatures(?array $signatures): ?array
    {
        if (null === $signatures) {
            return null;
        }

        $normalizedSignatures = $signatures;

        if (isset($signatures['script-src'])) {
            $normalizedSignatures['script-src'] = implode(
                ' ',
                array_map(static function (string $value): string {
                    return \sprintf('\'%s\'', $value);
                }, $signatures['script-src'])
            );
        }

        if (isset($signatures['style-src'])) {
            $normalizedSignatures['style-src'] = implode(
                ' ',
                array_map(static function (string $value): string {
                    return \sprintf('\'%s\'', $value);
                }, $signatures['style-src'])
            );
        }

        return $normalizedSignatures;
    }
}
