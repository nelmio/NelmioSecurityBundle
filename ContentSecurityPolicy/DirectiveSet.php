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

class DirectiveSet
{
    const TYPE_SRC_LIST = 'source-list';
    const TYPE_MEDIA_TYPE_LIST = 'media-type-list';
    const TYPE_ANCESTOR_SRC_LIST = 'ancestor-source-list';
    const TYPE_URI_REFERENCE = 'uri-reference';
    const TYPE_NO_VALUE = 'no-value';

    private static $directiveNames = array(
        'default-src' => self::TYPE_SRC_LIST,
        'script-src' => self::TYPE_SRC_LIST,
        'object-src' => self::TYPE_SRC_LIST,
        'style-src' => self::TYPE_SRC_LIST,
        'img-src' => self::TYPE_SRC_LIST,
        'media-src' => self::TYPE_SRC_LIST,
        'frame-src' => self::TYPE_SRC_LIST,
        'font-src' => self::TYPE_SRC_LIST,
        'connect-src' => self::TYPE_SRC_LIST,
        'report-uri' => self::TYPE_URI_REFERENCE,
        'base-uri' => self::TYPE_SRC_LIST,
        'child-src' => self::TYPE_SRC_LIST,
        'form-action' => self::TYPE_SRC_LIST,
        'frame-ancestors' => self::TYPE_ANCESTOR_SRC_LIST,
        'plugin-types' => self::TYPE_MEDIA_TYPE_LIST,
        'block-all-mixed-content' => self::TYPE_NO_VALUE,
        'upgrade-insecure-requests' => self::TYPE_NO_VALUE,
    );

    private $directiveValues = array();

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

    public function buildHeaderValue()
    {
        $policy = array();
        foreach ($this->directiveValues as $name => $value) {
            if (true === $value) {
                $policy[] = $name;
            } elseif ($name === 'default-src' || $this->canNotBeFallbackedByDefault($name, $value)) {
                // prevents using the same value as default for a directive
                $policy[] = $name.' '.$value;
            }
        }

        return implode('; ', $policy);
    }

    public static function fromConfig(array $config, $kind)
    {
        $directiveSet = new self();
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
        // Only source-list can be fallbacked by default
        if (self::$directiveNames[$name] !== self::TYPE_SRC_LIST) {
            return true;
        }

        // let's fallback if directives are strictly equals
        return $value !== $this->getDirective('default-src');
    }
}
