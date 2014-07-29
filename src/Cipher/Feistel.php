<?php namespace hlin\security;

/**
 * @copyright (c) 2014, freia Team
 * @license BSD-2 <http://freialib.github.io/license.txt>
 * @package freia Library
 */
class FeistelCipher {

	/**
	 * @var int
	 */
	protected $key;

	/**
	 * Key must be an integer.
	 *
	 * @return static
	 */
	static function instance($key = null) {
		$i = new static;
		$i->setkey($key);
		return $i;
	}

	/**
	 * @return static $this
	 */
	function setkey($key) {
		$this->key = intval($key);
		return $this;
	}

	/**
	 * @return string numeric value
	 */
	function obfuscate($in) {
		$i = $in;
		$a = $i / static::$mod;
		$b = $i % static::$mod;
		$r = static::$feistelRounds;

		while ($r-- != 0) {
			$a = ($a + $this->f($b)) % static::$mod;
			$b = ($b + $this->f($a)) % static::$mod;
		}

		return static::pad5(base_convert($a, 10, 36))
		     . static::pad5(base_convert($b, 10, 36));
	}

	/**
	 * @return int
	 */
	function deobfuscate($in) {
		$a = intval(substr($in, 0, 5), 36);
		$b = intval(substr($in, 5, 10), 36);

		$r = static::$feistelRounds;

		while ($r-- != 0) {
			$b = ($b - $this->f($a)) % static::$mod;
			$a = ($a - $this->f($b)) % static::$mod;
		}

		$a = ($a + static::$mod) % static::$mod;
		$b = ($b + static::$mod) % static::$mod;

		return $a * static::$mod + $b;
	}

// ---- Feistel Cipher sub-functions ------------------------------------------

	/**
	 * @return int
	 */
	protected function f($x) {
		$a = 12 + 1;
		$c = 1361423303;
		$x = ($x + $this->key) % static::$mod;
		$r = static::$randRounds;

		while ($r-- != 0) {
			$x = ($a * $x + $c) % static::$mod;
		}

		return $x;
	}

	/**
	 * @return string
	 */
	protected function pad5($s) {
		return sprintf('%05s', $s);
	}

// ---- Feistel Cipher constants ----------------------------------------------

	protected static $feistelRounds = 4;
	protected static $randRounds = 4;
	protected static $mod = 60466176;

} # class
