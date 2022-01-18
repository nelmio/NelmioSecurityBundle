<?php

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

class DirectiveSet
{
    const TYPE_SRC_LIST = 'source-list';
    const TYPE_SRC_LIST_NOFB = 'source-list-no-fallback';
    const TYPE_MEDIA_TYPE_LIST = 'media-type-list';
    const TYPE_ANCESTOR_SRC_LIST = 'ancestor-source-list';
    const TYPE_URI_REFERENCE = 'uri-reference';
    const TYPE_NO_VALUE = 'no-value';

    private static $directiveNames = array(
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
    );

    private $directiveValues = array();
    private $level1Fallback = true;
    private $policyManager = null;

    public function __construct(PolicyManager $policyManager)
    {
        $this->policyManager = $policyManager;
    }

    public function setLevel1Fallback($bool)
    {
        $this->level1Fallback = (bool) $bool;
    }

    public function getDirective($name)
    {
        $this->checkDirectiveName($name);

        if (array_key_exists($name, $this->directiveValues)) {
            return $this->directiveValues[$name];
        }

        return '';
    }

    public function setDirective($name, $value)
    {
        $this->checkDirectiveName($name);
        if (self::$directiveNames[$name] === self::TYPE_NO_VALUE) {
            if ($value) {
                $this->directiveValues[$name] = true;
            } else {
                unset($this->directiveValues[$name]);
            }
        } elseif ($value) {
            $this->directiveValues[$name] = $value;
        } else {
            unset($this->directiveValues[$name]);
        }
    }

    public function setDirectives(array $directives)
    {
        foreach ($directives as $name => $value) {
            $this->setDirective($name, $value);
        }
    }

    public function buildHeaderValue(Request $request, array $signatures = null)
    {
        $policy = array();

        if (isset($signatures['script-src'])) {
            $signatures['script-src'] = implode(' ', array_map(function ($value) { return sprintf('\'%s\'', $value); }, $signatures['script-src']));
        }
        if (isset($signatures['style-src'])) {
            $signatures['style-src'] = implode(' ', array_map(function ($value) { return sprintf('\'%s\'', $value); }, $signatures['style-src']));
        }

        $availableDirectives = $this->policyManager->getAvailableDirective($request);

        foreach ($this->directiveValues as $name => $value) {
            if (!in_array($name, $availableDirectives, true)) {
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
                    $policy[] = $name.' '.$value.' '.'\'unsafe-inline\' '.$signatures[$name];
                } else {
                    $policy[] = $name.' '.$value.' '.$signatures[$name];
                }
            } elseif ($this->canNotBeFallbackedByDefault($name, $value)) {
                $policy[] = $name.' '.$value;
            }
        }

        if (!empty($signatures)) {
            $defaultSrc = $this->getDirective('default-src');
            $isDefaultSrcSet = $defaultSrc !== '';

            if ($isDefaultSrcSet && false === strpos($defaultSrc, '\'unsafe-inline\'')) {
                $unsafeInline = $this->level1Fallback ? ' \'unsafe-inline\'' : '';

                if (empty($this->directiveValues['script-src']) && isset($signatures['script-src'])) {
                    $policy[] = 'script-src '.$defaultSrc.$unsafeInline.' '.$signatures['script-src'];
                }

                if (empty($this->directiveValues['style-src']) && isset($signatures['style-src'])) {
                    $policy[] = 'style-src '.$defaultSrc.$unsafeInline.' '.$signatures['style-src'];
                }
            }
        }

        return implode('; ', $policy);
    }

    public static function fromConfig(PolicyManager $policyManager, array $config, $kind)
    {
        $directiveSet = new self($policyManager);
        $directiveSet->setLevel1Fallback(isset($config[$kind]) ? $config[$kind]['level1_fallback'] : false);

        if (!array_key_exists($kind, $config)) {
            return $directiveSet;
        }

        $parser = new ContentSecurityPolicyParser();
        foreach (self::getNames() as $name => $type) {
            if (!array_key_exists($name, $config[$kind])) {
                continue;
            }

            $directiveSet->setDirective($name, $parser->parseSourceList($config[$kind][$name]));
        }

        return $directiveSet;
    }

    public static function getNames()
    {
        return self::$directiveNames;
    }

    private function checkDirectiveName($name)
    {
        if (!array_key_exists($name, self::$directiveNames)) {
            throw new \InvalidArgumentException('Unknown CSP directive name: '.$name);
        }
    }

    private function canNotBeFallbackedByDefault($name, $value)
    {
        if ($name === 'default-src') {
            return true;
        }

        // Only source-list can be fallbacked by default
        if (self::$directiveNames[$name] !== self::TYPE_SRC_LIST) {
            return true;
        }

        // let's fallback if directives are strictly equals
        return $value !== $this->getDirective('default-src');
    }
}
