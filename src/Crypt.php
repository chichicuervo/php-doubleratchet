<?php

namespace jbelich\DoubleRatchet;

use jbelich\DoubleRatchet\SchemaObject;
use jbelich\DoubleRatchet\Stateful;
use jbelich\DoubleRatchet\Protocol;

interface CryptInterface {

    const MODE_SENDER   = Protocol::MODE_SENDER;
    const MODE_RECEIVER = Protocol::MODE_RECEIVER;

    /**
     * Create new Diffie-Hellman private-public key pair
     *
     * @return string $key_pair
     */
    public function makeKeypair();

    /**
     * Extract the public key from a Diffie-Hellman key pair
     *
     * @param string $key_pair
     *
     * @return string $public_key
     */
    public function getPublicKey($key_pair);

    /**
     * Extract the secret key from a Diffie-Hellman key pair
     *
     * @param string $key_pair
     *
     * @return string $public_key
     */
    public function getSecretKey($key_pair);

    /**
     * Concatenate a public key and secret key into a Diffie-Hellman key pair
     *
     * @param string $public_key,
     * @param string $secret_key
     *
     * @return string $key_pair
     */
    public function getKeyPair($public_key, $secret_key);

    /**
     * Generate a Diffie-Hellman shared secret
     *
     * @param string $local_key_pair Your local key pair
     * @param string $public_key remote public key
     * @param int $mode MODE_SENDER|MODE_RECEIVER
     *
     * @return string $shared_secret
     */
    public function makeSharedSecret($local_key_pair, $public_key, $mode = self::MODE_RECEIVER);

    /**
     * return a random string of supplied length
     *
     * @param int $length
     *
     * @return string
     */
    public function getRandomBytes($length);

    /**
     * Encrypt a string
     *
     * @param string $message_key the encryption key
     * @param string $headerstring prepend to ciphertext output
     * @param string $plaintext string to be encrypted
     *
     * @return string $ciphertext
     */
    public function Encrypt($message_key, $headerstring, $plaintext);

    /**
     * Decrypt a string
     *
     * @param string $message_key the encryption key
     * @param string $headerstring prepend to ciphertext output
     * @param string $ciphertext string to be decrypted 
     *
     * @return string $plaintext
     */
    public function Decrypt($message_key, $headerstring, $ciphertext);

}

class Crypt extends SchemaObject {
    use Stateful;

    /**
     * Static Factory function to choose Cryptographic functionality
     *
     * @param State $obj State object
     * @param array $options array of function defaults. Supported keys:
     *      [ crypt_class => Class name for Crypt function to be invoked (Default: Crypt::class + \Sodium\Ietf\Chacha20Poly1305)]
     *
     * @return CryptInterface $crypt
     */
    static public function factory($state, array $options = [])
    {
        $options = $options + [
            // 'crypt_class' => __CLASS__ // we can't allow self-instanciation
            'crypt_class' => __CLASS__ . '\\Sodium\\Ietf\\Chacha20Poly1305'
        ];

        if (!class_exists($options['crypt_class']) || !is_subclass_of($options['crypt_class'], __CLASS__) || !is_subclass_of($options['crypt_class'], CryptInterface::class)) {
            throw new \InvalidArgumentException('Options[crypt_class] must extend Crypt and implement CryptInterface');
        }

        return new $options['crypt_class']($state, $options);
    }

    /**
     * base constructor
     *
     * @param State $obj State object
     * @param array $options array of function defaults. Supported keys:
     *      [
     *          crypt_schema => additional schema keys (Default: [])
     *          crypt_defaults => additional schema default values (Default: [])
     *      ]
     *
     * @return CryptInterface $crypt
     */
    protected function __construct($state, array $options = [])
    {
        $this->setState($state);
        parent::__construct($options['crypt_schema'] ?? [], $options['crypt_defaults'] ?? []);
    }

}
