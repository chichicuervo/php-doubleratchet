<?php

namespace jbelich\DoubleRatchet;

use jbelich\DoubleRatchet\Crypt;
use jbelich\DoubleRatchet\Kdf;
use jbelich\DoubleRatchet\Header;
use jbelich\DoubleRatchet\DefaultContainer as Container;

/**
 * Stores the current DoubleRatchet session state
 */
class State implements \ArrayAccess, \Serializable {

    private $container;

    /**
     * @param int $mode
     * @param array $values initial default values
     * @param array $options
     */
    public function __construct($mode, array $values = NULL, array $options = [])
    {
        $options = ['mode' => $mode] + $options;

        if ($values) {
            $this->fromArray([$options, $values]);
        }
    }

    /**
     * Sets the $state object data from array
     *
     * @param array $state [$options, $values]. Supported $options keys:
     *      [
     *          remote_public_key,
     *          associated_data => the AD required for AEAD encryption. (Default NULL = AD is generated from random bytes),
     *          local_key_pair => Your local Diffie-Hellman keypair (Default = generated from Crypt object),
     *          shared_key => Initial Diffie-Hellman shared secret, or most recent Root Key (Default: generated from local_key_pair and remote_public_key)
     *      ]
     */
    public function fromArray(array $state)
    {
        $options = $state[0];
        $values = $state[1];

        $this->container = new Container($values + [
            'init_opts' => function ($c) use ($options) {
                return $options;
            },
            'remote_public_key' => $options['remote_public_key'] ?? NULL,
            'associated_data' => $options['associated_data'] ?? NULL,
            'nonce' => $options['nonce'] ?? __CLASS__,
            'crypt' => function ($c) use ($options) {
                return Crypt::factory($c, $options);
            },
            'kdf' => function ($c) use ($options) {
                return Kdf::factory($c, $options);
            },
            'header' => function ($c) use ($options) {
                return Header::factory($c, $options);
            },
            'local_key_pair' => function ($c) use ($options) {
                return $options['local_key_pair'] ?? $c['crypt']->makeKeypair();
            },
            'shared_key' => function ($c) use ($options) { // somethign tells me $mode is going to be a container var and modified by code
                return $options['shared_key'] ?? $c['crypt']->makeSharedSecret($c['local_key_pair'], $c['remote_public_key'], $options['mode'] ?? $mode);
            },
            'root_key' =>  function ($c) {
                return $c['shared_key'];
            }
        ]);

        $this->container['local_public_key'] = $this->container->factory(function($c) {
            return $c['crypt']->getPublicKey($c['local_key_pair']);
        });

        return $this;
    }

    /**
     * Gets an array representation of the $state object, for sleep purposes
     *
     * @return array [$options, $values];
     */
    public function toArray()
    {
        $options = [
            'local_key_pair' => $this->container['local_key_pair'],
            'shared_key' => $this->container['root_key'],
        ] + $this->container['init_opts'];

        $nosave = ['init_opts','root_key','local_public_key'];

        $values = [];
        foreach($this->container->keys() as $key) {
            if (in_array($key, $nosave) || isset($options[$key])) continue;

            if ($this->container[$key] instanceof KdfInterface) {
                $options['kdf_class'] = get_class($this->container[$key]);
                continue;

            } elseif ($this->container[$key] instanceof CryptInterface) {
                $options['crypt_class'] = get_class($this->container[$key]);
                continue;

            } elseif ($this->container[$key] instanceof Header) {
                $options['header_class'] = get_class($this->container[$key]);
                continue;

            } elseif (!$this->container[$key] instanceof \Closure) {
                $values[$key] = $this->container[$key];
            }
        }

        return [$options, $values];
    }

    public function serialize()
    {
        return serialize($this->toArray());
    }

    public function unserialize($serialized)
    {
        $state = unserialize($serialized);

        if (!is_array($state) || count($state) != 2) {
            throw new \InvalidArgumentException('Invalid serialized state string.');
        }

        return $this->fromArray([$state[0], $state[1]]);
    }

    public function offsetExists($offset)
    {
        return $this->container->offsetExists($offset);
    }

    public function offsetGet($offset)
    {
        return $this->container->offsetGet($offset);
    }

    public function offsetSet($offset, $value)
    {
        return $this->container->offsetSet($offset, $value);
    }

    public function offsetUnset($offset)
    {
        return $this->container->offsetUnset($offset);
    }

}
