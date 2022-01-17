<?php

namespace Nelmio\SecurityBundle\Twig\Node;

/*
 * This file is part of the Nelmio SecurityBundle.
 *
 * (c) Nelmio <hello@nelm.io>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Twig\Compiler;
use Twig\Node\Node;

class CSPNode extends Node
{
    private $sha;
    private $directive;

    public function __construct(Node $body, $lineno, $tag, $directive, $sha = null)
    {
        parent::__construct(array('body' => $body), array(), $lineno, $tag);
        $this->sha = $sha;
        $this->directive = $directive;
    }

    /**
     * @return void
     */
    public function compile(Compiler $compiler)
    {
        $body = $this->getNode('body');

        if (null !== $this->sha) {
            $output = "\$this->env->getExtension('Nelmio\SecurityBundle\Twig\NelmioCSPTwigExtension')->getListener()->addSha('{$this->directive}', '{$this->sha}');\necho ob_get_clean();\n";
        } elseif ($this->directive === 'script-src') {
            $output = "\$script = ob_get_clean();\n\$this->env->getExtension('Nelmio\SecurityBundle\Twig\NelmioCSPTwigExtension')->getListener()->addScript(\$script);\necho \$script;\n";
        } elseif ($this->directive === 'style-src') {
            $output = "\$style = ob_get_clean();\n\$this->env->getExtension('Nelmio\SecurityBundle\Twig\NelmioCSPTwigExtension')->getListener()->addStyle(\$style);\necho \$style;\n";
        } else {
            throw new \InvalidArgumentException(sprintf('Unable to compile for directive "%s"', $this->directive));
        }

        $compiler
            ->addDebugInfo($this)
            ->write("ob_start();\n")
            ->subcompile($body)
            ->write($output)
        ;
    }
}
