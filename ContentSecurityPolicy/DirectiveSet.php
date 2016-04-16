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
    private static $directiveNames = array(
        'default-src',
        'script-src',
        'object-src',
        'style-src',
        'img-src',
        'media-src',
        'frame-src',
        'font-src',
        'connect-src',
        'report-uri'
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
        if ($value) {
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
            if ($name === 'default-src' || $value !== $this->getDirective('default-src')) {
                $policy[] = $name . ' ' . $value;
            }
        }

        return join('; ', $policy);
    }

    public static function fromConfig(array $config, $kind)
    {
        $directiveSet = new self();
        if (!array_key_exists($kind, $config)) {
            return $directiveSet;
        }

        $parser = new ContentSecurityPolicyParser();
        foreach (self::getNames() as $name) {
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
        if (!in_array($name, self::$directiveNames, true)) {
            throw new \InvalidArgumentException('Unknown CSP directive name: ' . $name);
        }
    }
}
