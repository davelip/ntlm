<?php namespace NTLM\NTLM

use Psr\Log\LoggerInterface;

class NTLM
{
    private $logger;

    public function __construct(LoggerInterface $logger = null)
    {
        $this->logger = $logger;
    }

    public function doSomething()
    {
        if ($this->logger) {
            $this->logger->info('Doing work');
        }
    }
}
