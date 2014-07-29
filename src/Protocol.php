<?php namespace hlin\security;

/**
 * @copyright (c) 2014, freia Team
 * @license BSD-2 <http://freialib.github.io/license.txt>
 * @package freia Library
 */
class Protocol implements \hlin\security\ProtocolSignature {

	use \hlin\ProtocolTrait;

	/**
	 * @return static
	 */
	static function instance() {
		return new static;
	}

	/**
	 * Relays are entities or routes, context is an array of values required for
	 * the match, among these values "owner" is a special idenfication value.
	 *
	 * For inpage elements you must provide attribute restrictions. An
	 * attribute is an element on the page.
	 *
	 * @return boolean
	 */
	function matches($entity, array $context = null, $attribute = null) {

		// cycle though acceptable entities
		foreach ($this->entities as $name) {
			// found an entity
			if ($name === $entity) {
				if ($this->parameters !== null) {
					// we check if every paramter registered for this permission
					// definition is set in the current test
					foreach ($this->parameters as $key => $values) {
						// we assume it doesn't match; ie. deny by default
						$match = false;
						// we get the value for the paramter definition, or null
						$param_value = isset($context[$key]) ? $context[$key] : null;
						// if we got NULL, it means the value wasn't set so we
						// fail the test. All paramters in the definition must
						// match, to at least one allowed value
						if ($param_value !== null) {
							// if it matched we go over the values in the
							// definition
							foreach ($values as $value) {
								// ... and check with the value we got
								if ($value === $param_value) {
									// we found a match
									$match = true;
									// break out of the values loop, but we
									// still need to continue check the rest of
									// the paramters in the definition
									break;
								}
							}
						}
						else { # parameter is not set
							// we fail the match
							return false;
						}

						// if we fail to match even 1 paramter then we fail the
						// match for the definition. All paramters must match
						// with at least one value
						if ($match == false) {
							return false;
						}
					}
				}
				else if ( ! empty($context) && ! $this->all_parameters) {
					// context requires paramters but rights only give access
					// to non-paramters; the resolution is that it's not allowed
					// unless the all_parameters flag was passed when creating
					// the protocol
					return false;
				}

				// every paramter matched to at least one value. Now we check if
				// we need a object check
				if ($attribute !== null) {

					$match = false;
					// if we do we go though all objects and check with the
					// test object

					// do we actually have anything to test?
					if ($this->attributes === null) {
						return false;
					}

					foreach ($this->attributes as $attr) {
						if ($attr === $attribute) {
							// match found
							$match = true;
							// no reason to go on
							break;
						}
					}

					// we return the results of our search
					return $match;
				}
				else { # no object defintion
					return true;
				}
			}
		}

		// the permission doesn't apply to the definition in question
		return false;
	}

} # class
