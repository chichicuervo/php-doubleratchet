<?php

namespace jbelich\DoubleRatchet;

use jbelich\DoubleRatchet\SchemaObject;
use jbelich\DoubleRatchet\Stateful;
use jbelich\DoubleRatchet\Protocol;

interface KdfInterface {

    public function nextChainKey($mode, array $options = []);

    public function nextMessageKey($mode, array $options = []);

}

class Kdf extends SchemaObject {
    use Stateful;

    const MODE_SENDER   = Protocol::MODE_SENDER;
    const MODE_RECEIVER = Protocol::MODE_RECEIVER;

    const DEFAULT_KEY_LENGTH  = 32;
    const DEFAULT_SHARED_SALT = __CLASS__;

    const VAR_KEY_LENGTH      = 'key_length';
    const VAR_SHARED_SALT     = 'shared_salt';

    static public function factory($state, array $options = [])
    {
        $options = $options + [
            // 'kdf_class' => __CLASS__ // we can't allow self-instanciation
            'kdf_class' => __CLASS__ . '\\HashHmac'
        ];

        if (!class_exists($options['kdf_class']) || !is_subclass_of($options['kdf_class'], __CLASS__) || !is_subclass_of($options['kdf_class'], KdfInterface::class)) {
            throw new \InvalidArgumentException('Options[kdf_class] must extend Kdf and implement KdfInterface');
        }

        return new $options['kdf_class']($state, $options);
    }

    protected function __construct($state, array $options = [])
    {
        $this->setState($state);
        parent::__construct($options['kdf_schema'] ?? [], $options['kdf_defaults'] ?? []);
    }

}
