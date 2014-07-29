<?php namespace hlin\security;

/**
 * Helper for creating protocols succintly in configuration files.
 *
 * @copyright (c) 2014, freia Team
 * @license BSD-2 <http://freialib.github.io/license.txt>
 * @package freia Library
 */
class Check {

	/**
	 * This method accepts both a single array of entities or list of parameters
	 * representing the array of entities.
	 *
	 * @return \hlin\security\ProtocolSignature
	 */
	static function entities(/* args... */) {

		$args = func_get_args();

		if (count($args) == 1 && is_array($args[0])) {
			$entities = $args[0];
		}
		else { # count != 1 || ! is_array(args[0])
			$entities = $args;
		}

		return \hlin\Protocol::instance()
			->entities($entities)
			->is('hlin.Check::entity Protocol');
	}

	/**
	 * This method accepts both a single array of attributes or list of
	 * parameters representing the array of attributes.
	 *
	 * @return \hlin\security\ProtocolSignature
	 */
	static function attrs($entity, array $args) {
		return \hlin\Protocol::instance()
			->entities([$entity])
			->attrs($args)
			->unrestricted()
			->is('hlin.Check::attrs Protocol');
	}

} # class
