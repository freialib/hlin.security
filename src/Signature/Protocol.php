<?php namespace hlin\security;

/**
 * @copyright (c) 2014, freia Team
 * @license BSD-2 <http://freialib.github.io/license.txt>
 * @package freia Library
 */
interface ProtocolSignature {

	/**
	 * This method accepts both a single array of entities or list of parameters
	 * representing the array of entities.
	 *
	 * @return static $this
	 */
	function entities(/* args... */);

	/**
	 * This method accepts both a single array of attributes or list of
	 * parameters representing the array of attributes.
	 *
	 * @return static $this
	 */
	function attrs(/* args... */);

	/**
	 * Constraints rule to only users who are NOT the owners of said object.
	 *
	 * @return static $this
	 */
	function only_others();

	/**
	 * Constraints rule to only users who are the owners of said object.
	 *
	 * @return static $this
	 */
	function only_owner();

	/**
	 * Resets constraint on ownership back to everybody.
	 *
	 * @return static $this
	 */
	function everybody();

	/**
	 * true = only owner of object
	 * false = everyone but owner of object
	 * null = everyone
	 *
	 * @return boolean|null
	 */
	function selfcontrol();

	/**
	 * @return static $this
	 */
	function allow($name, array $values);

	/**
	 * Grant unrestricted access to the given entities. ie. all parameters are
	 * allowed.
	 *
	 * @return static $this
	 */
	function unrestricted();

	/**
	 * Relays are entities or routes, context is an array of values required
	 * for the match, among these values "owner" is a special
	 * idenfication value.
	 *
	 * For inpage elements you must provide attribute restrictions.
	 * An attribute is an element on the page.
	 *
	 * @return boolean
	 */
	function matches($relay, array $context = null, $attribute = null);

	/**
	 * @return static $this
	 */
	function is($identifier);

	/**
	 * @return string
	 */
	function identifier();

} # signature
