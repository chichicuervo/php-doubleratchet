<?php

namespace jbelich\DoubleRatchet;

use jbelich\DoubleRatchet\SchemaObject;
use jbelich\DoubleRatchet\Stateful;
use jbelich\DoubleRatchet\Protocol;

interface CryptInterface {

    const MODE_SENDER   = Protocol::MODE_SENDER;
    const MODE_RECEIVER = Protocol::MODE_RECEIVER;

    public function makeKeypair();

    public function getPublicKey($key_pair);

    public function getSecretKey($key_pair);

    public function getKeyPair($public_key, $secret_key);

    public function makeSharedSecret($local_key_pair, $public_key, $mode = self::MODE_RECEIVER);

    public function getRandomBytes($length);

    public function Encrypt($message_key, $headerstring, $plaintext);

    public function Decrypt($message_key, $headerstring, $ciphertext);

}

class Crypt extends SchemaObject {
    use Stateful;

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

    protected function __construct($state, array $options = [])
    {
        $this->setState($state);
        parent::__construct($options['crypt_schema'] ?? [], $options['crypt_defaults'] ?? []);
    }

}
