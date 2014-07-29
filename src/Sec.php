<?php namespace hlin\security;

/**
 * Collection of helpful security functions.
 *
 * @copyright (c) 2014, freia Team
 * @license BSD-2 <http://freialib.github.io/license.txt>
 * @package freia Library
 */
class Sec {

	/**
	 * Given a password in plaintext the method will produce a verifier, salt
	 * and algorythm. You can provide an algorythm and/or salt and it will be used instead of
	 * a new one being generated.
	 *
	 * @return array [salt, verifier, algorythm]
	 */
	static function genpwd($apikey, $textpwd, $salt = null, $algorythm = 'sha512') {

		$pwd = [];

		// generate password salt and hash
		if ($salt === null) {
			$pwd['salt'] = hash($algorythm, (uniqid(rand(), true)), false);
		}
		else { # salt provided
			$pwd['salt'] = $salt;
		}

		$lockedpwd = hash_hmac($algorythm, $textpwd, $apikey, false);
		$pwd['verifier'] = hash_hmac($algorythm, $lockedpwd, $pwd['salt'], false);
		$pwd['algorythm'] = $algorythm;

		return $pwd;
	}

	/**
	 * @return boolean
	 */
	static function matchpwd($apikey, $textpwd, $verifier, $salt, $algorythm) {
		$pwd = static::genpwd($apikey, $textpwd, $salt, $algorythm);
		return $pwd['verifier'] == $verifier;
	}

} # class
