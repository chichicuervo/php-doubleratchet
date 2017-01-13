<?php

namespace jbelich\DoubleRatchet\Kdf;

use jbelich\DoubleRatchet\Kdf;
use jbelich\DoubleRatchet\KdfInterface;
use jbelich\DoubleRatchet\CryptInterface;

class HashHmac extends Kdf implements KdfInterface {

    const DEFAULT_ALGO       = 'sha512';
    const DEFAULT_NUM_KEYS   = 2;

    protected $schema = ['extra_keys', 'hash_algo'];

    public function nextChainKey($mode, array $options = [])
    {
        if ($mode !== self::MODE_SENDER && $mode != self::MODE_RECEIVER) {
            throw new \InvalidArgumentException('$mode must be either self::MODE_SENDER or self::MODE_RECEIVER');
        }

        if (!isset($this->state['crypt']) || !$this->state['crypt'] instanceof CryptInterface) {
            throw new \UnexpectedValueException('Invalid value for state[crypt]');
        }

        if (!isset($this->state['remote_public_key'])) {
            throw new \UnderflowException('state[remote_public_key] must be set.');
        }

        $options = $options + [
            'algo' => $this['hash_algo'] ?? self::DEFAULT_ALGO,
            'num_keys' => self::DEFAULT_NUM_KEYS,
            'key_length' => $this[self::VAR_KEY_LENGTH],
            'shared_salt' => $this[self::VAR_SHARED_SALT],
            'chain_key_name' => $mode === self::MODE_SENDER ? 'sender_chain_key' : 'receive_chain_key'
        ];

        if (!$options['key_length'] || $options['key_length'] < 0 || $options['key_length'] > 255) {
            throw new \OutOfBoundsException('key_length must be between 0 and 255');
        }
        if (!$options['num_keys'] || $options['num_keys'] < 2) {
            throw new \OutOfBoundsException('num_keys must be at least 2');
        }

        $new_shared = $this->state['crypt']->makeSharedSecret($this->state['local_key_pair'], $this->state['remote_public_key'], $mode);
        $prekey     = hash_hmac($options['algo'], $new_shared, $this->state['root_key'], TRUE);

        for ($key = $block = '', $i = 1, $l = $options['key_length'] * $options['num_keys'] ; strlen($key) < $l ; $i++) {
            $key .= $block = hash_hmac($options['algo'], $block . $options['shared_salt'] . chr($i), $prekey, TRUE);
        }

        if (FALSE === ($keys = str_split($key, $options['key_length']))) {
            throw new \LogicException(__METHOD__ . ' created no keys');
        }

        $this->state['root_key'] = array_shift($keys);
        $this->state[$options['chain_key_name']] = array_shift($keys);

        if ($keys) {
            $this['extra_keys'] = $keys;
        } else {
            unset($this['extra_keys']);
        }

        return $this->state[$options['chain_key_name']];
    }

    public function nextMessageKey($mode, array $options = [])
    {
        if ($mode !== self::MODE_SENDER && $mode != self::MODE_RECEIVER) {
            throw new \InvalidArgumentException('$mode must be either self::MODE_SENDER or self::MODE_RECEIVER');
        }

        $options = $options + [
            'algo' => $this['hash_algo'] ?? self::DEFAULT_ALGO,
            'key_length' => $this[self::VAR_KEY_LENGTH],
            'chain_key_name' => $mode === self::MODE_SENDER ? 'sender_chain_key' : 'receive_chain_key'
        ];
        if ($options['key_length'] < 0 || $options['key_length'] > 255) {
            throw new \OutOfBoundsException('key_length must be between 0 and 255');
        }

        $chain_key = $this->state[$options['chain_key_name']];

        $this->state[$options['chain_key_name']] = substr(hash_hmac($options['algo'], 0x02, $chain_key, TRUE), 0, $options['key_length']);

        return substr(hash_hmac($options['algo'], 0x01, $chain_key, TRUE), 0, $options['key_length']);
    }
}
