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

namespace Nelmio\SecurityBundle\ContentSecurityPolicy\Violation\Log;

use Nelmio\SecurityBundle\ContentSecurityPolicy\Violation\Report;

class LogFormatter implements LogFormatterInterface
{
    public function format(Report $report)
    {
        return 'Content-Security-Policy Violation Reported';
    }
}
