<?php namespace hlin\security;

/**
 * @copyright (c) 2014, freia Team
 * @license BSD-2 <http://freialib.github.io/license.txt>
 * @package freia Library
 */
class Auth implements \hlin\archetype\Authorizer {

	use \hlin\AuthorizerTrait;

	// initialization constants
	const Unidentified = null;
	const Guest = 'freia:GuestType';

	// authorization constants
	const Everybody  = null;
	const OnlyOwner  = true;
	const OnlyOthers = false;

	/**
	 * @var array
	 */
	protected $whitelist;

	/**
	 * @var array
	 */
	protected $blacklist;

	/**
	 * @var array
	 */
	protected $aliaslist;

	/**
	 * @var int
	 */
	protected $id;

	/**
	 * Most operations are on the current entity, so we require the current
	 * entity is set to facilitate the process; some operations also require
	 * the current entity to resolve.
	 *
	 * @return static
	 */
	static function instance(array $whitelist, array $blacklist, array $aliaslist, $main_entity_id = \hlin\Auth::Unidentified, $main_entity_role = \hlin\Auth::Guest, \hlin\archetype\Logger $logger = null) {

		$i = new static;

		$i->whitelist = $whitelist;
		$i->blacklist = $blacklist;
		$i->aliaslist = $aliaslist;

		$i->id = $main_entity_id;
		$i->role = $main_entity_role;

		$i->logger = $logger;

		return $i;
	}

	/**
	 * @return boolean
	 */
	function can($entity, array $context = null, $attribute = null, $user_role = null) {

		$this->last_instigator = null;
		$this->last_matched_role = null;
		$this->last_matched_type = 0; # no explicit pass nor ban

		// get role of current user
		$user_role = $user_role !== null ? $user_role : $this->role;

		// initial status
		$status = false; # unauthorized

		if (isset($this->whitelist[$user_role])) {
			// attempt to authorize
			$status = $this->match_check($this->whitelist[$user_role], $entity, $context, $attribute);
			$this->last_matched_type = 1; # direct pass
			! $status or $this->last_matched_role = $user_role;
		}

		// failed authorization? check aliases for addition rules
		if ( ! $status && isset($this->aliaslist[$user_role])) {
			foreach ($this->aliaslist[$user_role] as $alias) {
				if (isset($this->whitelist[$alias]) && $this->match_check($this->whitelist[$alias], $entity, $context, $attribute)) {
					$status = true; # authorized
					$this->last_matched_type = 2; # indirect pass
					$this->last_matched_role = $alias;
					break;
				}
			}
		}

		// authorized? confirm blacklist
		if ($status && isset($this->blacklist[$user_role]) && $this->match_check($this->blacklist[$user_role], $entity, $context, $attribute)) {
			$this->last_matched_role = $alias;
			$this->last_matched_type = 3; # ban
			$status = false; # cancel authorization
		}

		return $status;
	}

// ---- Private ---------------------------------------------------------------

	/**
	 * @return boolean
	 */
	protected function match_check(array $permissions, $entity, $context, $attribute) {

		if (isset($context['owner'])) {
			// if we need owner computations we store the user
			$user = $this->id;
		}

		// check if no exception exists
		foreach ($permissions as $permission) {
			// check permission
			if ($permission->matches($entity, $context, $attribute)) {
				// check self inference
				// null means it doens't require self nor require !self
				if ($permission->selfcontrol() !== \hlin\Auth::Everybody) {
					// if we didn't get an owner parameter we deny access
					if ( ! isset($context['owner']) || $context['owner'] == null) {
						// NOTE: there are objects that have NULL owner, it
						// means they were submitted anoynmously (usually) so
						// because there is no user access of this kind on them
						// makes no sense and only lead to attack vectors
						continue;
					}

					// permission only in effect if user is owner of object
					if ($permission->selfcontrol() == \hlin\Auth::OnlyOwner) {
						// route must be object belonging to owner
						if ($user == $context['owner']) {
							$this->last_instigator = $permission->identifier();

							// matched
							return true;
						}
					}
					// permission only in effect if user is NOT owner of object
					elseif ($permission->selfcontrol() == \hlin\Auth::OnlyOthers) {
						// route must be object NOT belonging to owner
						if ($user != $context['owner']) {
							$this->last_instigator = $permission->identifier();

							// matched
							return true;
						}
					}
				}
				else {  # self is NULL, no further checks required
					$this->last_instigator = $permission->identifier();

					// matched
					return true;
				}
			}
		}

		// failed match
		return false;
	}

} # class
