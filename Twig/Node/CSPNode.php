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

class CSPNode extends \Twig_Node
{
    private $sha;
    private $directive;

    public function __construct(\Twig_NodeInterface $body, $lineno, $tag, $directive, $sha = null)
    {
        parent::__construct(array('body' => $body), array(), $lineno, $tag);
        $this->sha = $sha;
        $this->directive = $directive;
    }

    public function compile(\Twig_Compiler $compiler)
    {
        $body = $this->getNode('body');

        if (null !== $this->sha) {
            $output = "\$this->env->getExtension('nelmio-csp')->getListener()->addSha('{$this->directive}', '{$this->sha}');\necho ob_get_clean();\n";
        } elseif ($this->directive === 'script-src') {
            $output = "\$script = ob_get_clean();\n\$this->env->getExtension('nelmio-csp')->getListener()->addScript(\$script);\necho \$script;\n";
        } elseif ($this->directive === 'style-src') {
            $output = "\$style = ob_get_clean();\n\$this->env->getExtension('nelmio-csp')->getListener()->addStyle(\$style);\necho \$style;\n";
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
