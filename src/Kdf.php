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

namespace jbelich\DoubleRatchet;

use jbelich\DoubleRatchet\SchemaObject;
use jbelich\DoubleRatchet\Stateful;
use jbelich\DoubleRatchet\Protocol;

interface KdfInterface {

    /**
     * HKDF function to generate next Root Key and next send|receive Chain key
     *
     * @param int $mode Kdf::MODE_SENDER|Kdf::MODE_RECEIVER
     * @param array $options array of function defaults.
     *
     * @return string (send|receive)_chain_key
     */
    public function nextChainKey($mode, array $options = []);

    /**
     * KDF function to generate next Message Key and next Send|Receive Chain Key
     *
     * @param int $mode Kdf::MODE_SENDER|Kdf::MODE_RECEIVER
     * @param array $options array of function defaults.
     *
     * @return string $message_key
     */
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

    /**
     * Static Factory function to choose KDFs
     *
     * @param State $obj State object
     * @param array $options array of function defaults. Supported keys:
     *      [ kdf_class => Class name for KDF function to be invoked (Default: HashHmac)]
     *
     * @return KdfInterface $kdf
     */
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

    /**
     * base constructor
     *
     * @param State $obj State object
     * @param array $options array of function defaults. Supported keys:
     *      [
     *          kdf_schema => additional schema keys (Default: [])
     *          kdf_defaults => additional schema default values (Default: [])
     *      ]
     *
     * @return KdfInterface $kdf
     */
    protected function __construct($state, array $options = [])
    {
        $this->setState($state);
        parent::__construct($options['kdf_schema'] ?? [], $options['kdf_defaults'] ?? []);
    }

}
