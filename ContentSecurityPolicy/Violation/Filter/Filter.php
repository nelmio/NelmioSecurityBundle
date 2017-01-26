<?php

/*
 * This file is part of the Nelmio SecurityBundle.
 *
 * (c) Nelmio <hello@nelm.io>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Nelmio\SecurityBundle\ContentSecurityPolicy\Violation\Filter;

use Nelmio\SecurityBundle\ContentSecurityPolicy\Violation\Report;
use Symfony\Component\HttpFoundation\Request;

class Filter
{
    private $noiseDetectors = array();

    public function __construct(array $noiseDetectors = array())
    {
        foreach ($noiseDetectors as $noiseDetector) {
            $this->addNoiseDetector($noiseDetector);
        }
    }

    public function addNoiseDetector(NoiseDetectorInterface $noiseDetector)
    {
        $this->noiseDetectors[] = $noiseDetector;
    }

    public function filter(Request $request, Report $report)
    {
        foreach ($this->noiseDetectors as $noiseDetector) {
            if ($noiseDetector->match($report, $request)) {
                return true;
            }
        }

        return false;
    }
}
