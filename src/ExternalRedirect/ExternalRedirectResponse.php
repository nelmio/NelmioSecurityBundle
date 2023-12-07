<?php

namespace Nelmio\SecurityBundle\ExternalRedirect;

use Symfony\Component\HttpFoundation\RedirectResponse;

class ExternalRedirectResponse extends RedirectResponse
{
    /**
     * @var string[]
     */
    private array $allowedHosts;

    /**
     * @param string[] $allowedHosts
     * @param string[] $headers
     */
    public function __construct(string $url, array $allowedHosts, int $status = 302, array $headers = [])
    {
        $this->allowedHosts = $allowedHosts;
        parent::__construct($url, $status, $headers);
    }

    /**
     * @return string[]
     */
    public function getAllowedHosts(): array
    {
        return $this->allowedHosts;
    }
}
