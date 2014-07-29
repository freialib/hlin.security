<?php namespace hlin\security;

/**
 * @copyright (c) 2014, freia Team
 * @license BSD-2 <http://freialib.github.io/license.txt>
 * @package freia Library
 */
trait ProtocolTrait {

	/**
	 * @var array
	 */
	protected $entities;

	/**
	 * @var array
	 */
	protected $attributes;

	/**
	 * @var array
	 */
	protected $parameters;

	/**
	 * @var boolean
	 */
	protected $all_parameters = false;

	/**
	 * null is a control value. If the attribute is set to null this means
	 * there is no self constraint in action. Otherwise, if the value is a
	 * boolean then if the value is true the permission will only apply if the
	 * owner in context is the owner of the object, else if it is false then
	 * the constraint will only apply if the owner of the object is NOT the
	 * user in question; eg. "+1" feature only applies to everyone that is not
	 * the owner of said object, similarly a "edit" feature automatically
	 * applies if the user trying to edit is the owner of the resource
	 *
	 * @var boolean|null
	 */
	protected $self = null;

	/**
	 * This method accepts both a single array of entities or list of
	 * parameters representing the array of entities.
	 *
	 * @return static $this
	 */
	function entities(/* args... */) {

		$entities = func_get_args();

		if (count($entities) == 1 && is_array($entities[0])) {
			$this->entities = $entities[0];
		}
		else { # count != 1 || ! is_array(entities[0])
			$this->entities = $entities;
		}

		return $this;
	}

	/**
	 * This method accepts both a single array of attributes or list of
	 * parameters representing the array of attributes.
	 *
	 * @return static $this
	 */
	function attrs(/* args... */) {

		$attrs = func_get_args();

		if (count($attrs) == 1 && is_array($attrs[0])) {
			$this->attributes = $attrs[0];
		}
		else { # count != 1 || ! is_array(entities[0])
			$this->attributes = $attrs;
		}

		return $this;
	}

	/**
	 * Constraints rule to only users who are NOT the owners of said object.
	 *
	 * @return static $this
	 */
	function only_others() {
		$this->self = false;
		return $this;
	}

	/**
	 * Constraints rule to only users who are the owners of said object.
	 *
	 * @return static $this
	 */
	function only_owner() {
		$this->self = true;
		return $this;
	}

	/**
	 * Resets constraint on ownership back to everybody.
	 *
	 * @return static $this
	 */
	function everybody() {
		$this->self = null;
		return $this;
	}

	/**
	 * @return boolean|null
	 */
	function selfcontrol() {
		return $this->self;
	}

	/**
	 * @return static $this
	 */
	function allow($name, array $values) {
		$this->parameters or $this->parameters = array();
		$this->parameters[$name] = $values;
		return $this;
	}

	/**
	 * Grant unrestricted access to the given entities.
	 * ie. all parameters are allowed.
	 *
	 * @return static $this
	 */
	function unrestricted() {
		$this->all_parameters = true;
		return $this;
	}

	/**
	 * @var string
	 */
	protected $identifier = 'Anonymous Custom Protocol';

	/**
	 * @return static $this
	 */
	function is($identifier) {
		$this->identifier = $identifier;
		return $this;
	}

	/**
	 * @return string
	 */
	function identifier() {
		return $this->identifier;
	}

} # trait
