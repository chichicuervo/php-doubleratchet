<?php
/**
 *
 * Copyright (C) 2017 Jason E Belich <jason@belich.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
**/

namespace jbelich\DoubleRatchet\Kdf;

use jbelich\DoubleRatchet\Kdf;
use jbelich\DoubleRatchet\KdfInterface;
use jbelich\DoubleRatchet\CryptInterface;

class HashHmac extends Kdf implements KdfInterface {

    const DEFAULT_ALGO       = 'sha512';
    const DEFAULT_NUM_KEYS   = 2;

    protected $schema = ['extra_keys', 'hash_algo'];

    /**
     * HKDF function to generate next Root Key and next send|receive Chain key
     *
     * @param int $mode Kdf::MODE_SENDER|Kdf::MODE_RECEIVER
     * @param array $options array of function defaults. supported keys:
     *      [
     *          hash_algo => Hash digest algorithm (Default: $state[hash_algo] or sha512),
     *          num_keys => number of keys to generate (Default: 2 [root key and next chain key]),
     *          key_length => key length in bytes (Default: $state[key_length] or 32),
     *          shared_salt => Shared Salt for HMAC generation (Default: $state[shared_salt] or "\jbelich\DoubleRatchet\Kdf")
     *          chain_key_name => which chain key to update (Default determined by $mode)
     *      ]
     *
     * @return string (send|receive)_chain_key
     *
     * @throws InvalidArgumentException
     * @throws UnexpectedValueException
     * @throws UnderflowException
     * @throws OutOfBoundsException
     * @throws LogicException
     */
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
            'hash_algo' => $this['hash_algo'] ?? self::DEFAULT_ALGO,
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
        $prekey     = hash_hmac($options['hash_algo'], $new_shared, $this->state['root_key'], TRUE);

        for ($key = $block = '', $i = 1, $l = $options['key_length'] * $options['num_keys'] ; strlen($key) < $l ; $i++) {
            $key .= $block = hash_hmac($options['hash_algo'], $block . $options['shared_salt'] . chr($i), $prekey, TRUE);
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

    /**
     * KDF function to generate next Message Key and next Send|Receive Chain Key
     *
     * @param int $mode Kdf::MODE_SENDER|Kdf::MODE_RECEIVER
     * @param array $options array of function defaults. supported keys:
     *      [
     *          hash_algo => Hash digest algorithm (Default: $state[hash_algo] or sha512),
     *          key_length => key length in bytes (Default: $state[key_length] or 32),
     *          chain_key_name => which chain key to update (Default determined by $mode)
     *      ]
     *
     * @return string $message_key
     *
     * @throws InvalidArgumentException
     * @throws OutOfBoundsException
     */
    public function nextMessageKey($mode, array $options = [])
    {
        if ($mode !== self::MODE_SENDER && $mode != self::MODE_RECEIVER) {
            throw new \InvalidArgumentException('$mode must be either self::MODE_SENDER or self::MODE_RECEIVER');
        }

        $options = $options + [
            'hash_algo' => $this['hash_algo'] ?? self::DEFAULT_ALGO,
            'key_length' => $this[self::VAR_KEY_LENGTH],
            'chain_key_name' => $mode === self::MODE_SENDER ? 'sender_chain_key' : 'receive_chain_key'
        ];
        if ($options['key_length'] < 0 || $options['key_length'] > 255) {
            throw new \OutOfBoundsException('key_length must be between 0 and 255');
        }

        $chain_key = $this->state[$options['chain_key_name']];

        $this->state[$options['chain_key_name']] = substr(hash_hmac($options['hash_algo'], 0x02, $chain_key, TRUE), 0, $options['key_length']);

        return substr(hash_hmac($options['hash_algo'], 0x01, $chain_key, TRUE), 0, $options['key_length']);
    }
}
