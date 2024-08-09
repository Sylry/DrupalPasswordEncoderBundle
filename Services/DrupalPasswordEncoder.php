<?php
namespace Mdespeuilles\DrupalPasswordEncoderBundle\Services;

use Mdespeuilles\DrupalPasswordEncoderBundle\Services\Password\PhpassHashedPassword;
use Symfony\Component\PasswordHasher\PasswordHasherInterface;

class DrupalPasswordEncoder implements PasswordHasherInterface
{
    const DRUPAL_HASH_COUNT = 15;
    
    /**
     * @var \Mdespeuilles\DrupalPasswordEncoderBundle\Services\Password\PhpassHashedPassword
     */
    protected $drupalPasswordService;
    
    /**
     * DrupalPasswordEncoder constructor.
     */
    public function __construct()
    {
        $this->drupalPasswordService = new PhpassHashedPassword(self::DRUPAL_HASH_COUNT);
    }
    
    /**
     * Encode a password to a Drupal way
     *
     * @param string $plainPassword
     * @return string
     */
    public function hash(string $plainPassword): string
    {
        return $this->drupalPasswordService->hash($plainPassword);
    }
    
    /**
     * Check if password is valid
     *
     * @param string $hashedPassword
     * @param string $plainPassword
     * @return bool
     */
    public function verify(string $hashedPassword, string $plainPassword): bool
    {
        return $this->drupalPasswordService->check($plainPassword, $hashedPassword);
    }

    /**
     * {@inheritdoc}
     */
    public function needsRehash(string $encoded): bool
    {
        return true;
    }
}
