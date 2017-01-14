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

/**
 * Trait to simplify object accesss to the DoubleRatchet\State
 */
trait Stateful {

    protected $state;

    /**
     * $state settor
     *
     * @param array|ArrayAccess $state Protocol State Object
     *
     * @return self
     *
     * @throws InvalidArgumentException
     */
    public function setState($state)
    {
        if (!is_array($state) && !$state instanceof \ArrayAccess) {
            throw new \InvalidArgumentException('$state must be an array or implement \ArrayAccess');
        }

        $this->state = $state;

        return $this;
    }

    /**
     * $state gettor
     *
     * @return array|ArrayAccess
     */
    public function getState()
    {
        if (!isset($this->state)) {
            throw new \DomainException('$state must be set for ' . get_class($this));
        }

        return $this->state;
    }

    /**
     * Syntactic sugar to overload ArrayAccess's offsetGet()
     *
     * @throws BadMethodCallException if host class is not ArrayAccess
     */
    public function offsetGet($offset)
    {
        if (!$this instanceof \ArrayAccess) {
            throw new \BadMethodCallException('use of offsetGet() requires class ' . get_class($this) . ' to implement ArrayAccess');
        }

        if ($this instanceof SchemaObject) {
            if(!$this->offsetIsset($offset) && isset($this->state[$offset])) {
                $this->offsetSet($offset, $this->state[$offset]);
            }
        } elseif (!$this->offsetExists($offset) && isset($this->state[$offset])) {
            $this->offsetSet($offset, $this->state[$offset]);
        }

        return parent::offsetGet($offset);
    }
}
