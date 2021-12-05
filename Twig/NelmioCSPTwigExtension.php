<?php

/*
 * This file is part of the Nelmio SecurityBundle.
 *
 * (c) Nelmio <hello@nelm.io>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Nelmio\SecurityBundle\Twig;

use Nelmio\SecurityBundle\ContentSecurityPolicy\ShaComputer;
use Nelmio\SecurityBundle\EventListener\ContentSecurityPolicyListener;
use Nelmio\SecurityBundle\Twig\TokenParser\CSPScriptParser;
use Nelmio\SecurityBundle\Twig\TokenParser\CSPStyleParser;
use Twig\Extension\AbstractExtension;
use Twig\TwigFunction;

class NelmioCSPTwigExtension extends AbstractExtension
{
    private $listener;
    private $shaComputer;

    public function __construct(ContentSecurityPolicyListener $listener, ShaComputer $shaComputer)
    {
        $this->listener = $listener;
        $this->shaComputer = $shaComputer;
    }

    /**
     * @return array
     */
    public function getTokenParsers()
    {
        return array(new CSPScriptParser($this->shaComputer), new CSPStyleParser($this->shaComputer));
    }

    public function getListener()
    {
        return $this->listener;
    }

    public function getName()
    {
        return 'Nelmio\\SecurityBundle\\Twig\\NelmioCSPTwigExtension';
    }

    /**
     * @return array
     */
    public function getFunctions()
    {
        return array(
            new TwigFunction('csp_nonce', array($this, 'getCSPNonce')),
        );
    }

    public function getCSPNonce($usage = null)
    {
        if (null === $nonce = $this->listener->getNonce($usage)) {
            throw new \RuntimeException('You must enable nonce to use this feature');
        }

        return $nonce;
    }
}
