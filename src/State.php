<?php

namespace jbelich\DoubleRatchet;

use jbelich\DoubleRatchet\Crypt;
use jbelich\DoubleRatchet\Kdf;
use jbelich\DoubleRatchet\Header;
use jbelich\DoubleRatchet\DefaultContainer as Container;

class State implements \ArrayAccess, \Serializable {

    private $container;

    public function __construct($mode, array $values = NULL, array $options = [])
    {
        $options = ['mode' => $mode] + $options;

        if ($values) {
            $this->fromArray([$options, $values]);
        }
    }

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
