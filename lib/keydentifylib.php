<?php
/**
 * Keydentify SDK PHP Web
 *
 * Keydentify(tm) : Two Factor Authentication (http://www.keydentify.com)
 * Copyright (c) SAS Keydentify.  (http://www.keydentify.com)
 *
 * Licensed under The MIT License
 * For full copyright and license information, please see the LICENSE.txt
 * Redistributions of files must retain the above copyright notice.
 *
 * @copyright     Copyright (c) SAS Keydentify.  (http://www.keydentify.com)
 * @link          http://www.keydentify.com Keydentify(tm) Two Factor Authentication
 * @license       http://www.opensource.org/licenses/mit-license.php MIT License
 */
require_once('sha256.inc.php');
define('KEYDENTIFY_SERVER', 'https://app.keydentify.com');

class KeydentifyLib {

	protected static function postData($url, $post_fields) {
	
		$output = false;
	
		if (!extension_loaded('curl')) {
			$postdata = http_build_query($post_fields);
			$opts = array('http' =>
					array(
							'method'  => 'POST',
							'header'  => 'Content-type: application/x-www-form-urlencoded',
							'content' => $postdata
					)
			);
	
			$context  = stream_context_create($opts);
			$output = file_get_contents($url, false, $context);
		} else {
			$c = curl_init();
			curl_setopt($c, CURLOPT_URL, $url);
			curl_setopt($c, CURLOPT_RETURNTRANSFER, true);
			curl_setopt($c, CURLOPT_HEADER, false);
			curl_setopt($c, CURLOPT_AUTOREFERER, true);
			curl_setopt($c, CURLOPT_POST,true);
			curl_setopt($c, CURLOPT_POSTFIELDS, http_build_query($post_fields));
			curl_setopt($c, CURLOPT_SSLVERSION, 3);
			$output = curl_exec($c);
			//var_dump(curl_error($c));
			//var_dump($output);
			//if($output === false) {trigger_error('Erreur curl : '.curl_error($c),E_USER_WARNING);}
			curl_close($c);
		}
	
		return $output;
	}
	
	protected static function encryptChallenge($key, $challenge) {
		if (extension_loaded('mcrypt')) {
			try {
				require_once('mcrypt.php');
				$hkMCrypt = new HKMCrypt();

				$iv = KeydentifyLib::buildRandomKey(32);
				$challenge = $hkMCrypt->encrypt($challenge, md5($key), $iv).':'.$iv;
			} catch (Exception $e) {
			}
		}
		return $challenge;
	}

	protected static function decryptChallenge($key, $challenge) {
		if (extension_loaded('mcrypt')) {
			require_once('mcrypt.php');
			$hkMCrypt = new HKMCrypt();

			list($cryptedData, $iv) = explode(":", $challenge);
			$challenge = $hkMCrypt->decrypt($cryptedData, md5($key), $iv);
		}
		return $challenge;
	}

	protected static function buildCSRF($authType, $secretKey, $timeOut, $delay, $token, $challenge, $serviceId, $serviceUserId, $redirectTo, $login, $extra = '') {
		return sha256($authType.$timeOut.$delay.$token.$challenge.sha256($secretKey).$serviceId.$serviceUserId.$redirectTo.$login.$extra);
	}

	/*
	* PBKDF2 key derivation function as defined by RSA's PKCS #5: https://www.ietf.org/rfc/rfc2898.txt
	* $message - The message.
	* $salt - A salt that is unique to the message.
	* $count - Iteration count. Higher is better, but slower. Recommended: At least 1024.
	* $algorithm - The hash algorithm to use. Recommended: SHA256
	* $key_length - The length of the derived key in bytes.
	* $raw_output - If true, the key is returned in raw binary format. Hex encoded otherwise.
	* Returns: A $key_length-byte key derived from the message and salt.
	*
	* Test vectors can be found here: https://www.ietf.org/rfc/rfc6070.txt
	*
	* This implementation of PBKDF2 was originally created by defuse.ca
	* With improvements by variations-of-shadow.com
	*/
	protected static function pbkdf2($message, $salt, $count = 1024, $algorithm = 'sha1', $key_length = 80) {
		$algorithm = strtolower($algorithm);
		if(!in_array($algorithm, hash_algos(), true))
			return 'PBKDF2 ERROR: Invalid hash algorithm.';
		if($count <= 0 || $key_length <= 0)
			return 'PBKDF2 ERROR: Invalid parameters.';

		$hash_length = strlen(hash($algorithm, "", true));
		$block_count = ceil($key_length / $hash_length);

		$output = "";
		for($i = 1; $i <= $block_count; $i++) {
			// $i encoded as 4 bytes, big endian.
			$last = $salt . pack("N", $i);
			// first iteration
			$last = $xorsum = hash_hmac($algorithm, $last, $message, true);
			// perform the other $count - 1 iterations
			for ($j = 1; $j < $count; $j++) {
				$xorsum ^= ($last = hash_hmac($algorithm, $last, $message, true));
			}
			$output .= $xorsum;
		}

		return substr(KeydentifyLib::base64_url_encode($output), 0, $key_length);
	}

	protected static function buildRandomKey($length) {
		$force = true;
		return substr(KeydentifyLib::base64_url_encode(openssl_random_pseudo_bytes($length, $force)), 0, $length);
	}
	
	protected static function base64_url_encode($input) {
		return strtr(base64_encode($input), '+/=', '-_,');
	}
}

if (!function_exists('openssl_random_pseudo_bytes')) {
	function openssl_random_pseudo_bytes($size) {
		$hexa = 'abcdef0123456789ABCDEF0123456789abcdef0123456789ABCDEF0123456789';
		$len=strlen($hexa)-1;

		$randomHex = '';
		for ($i=0; $i<$size; $i++) {
			$randomHex .= substr($hexa, rand(0, $len), 1);
		}

		return $randomHex;
	}
}

if (!function_exists('__')) {

	$i18nMessageLibs = array();
	$i18nMessageLibs['fr'] = array(
			'W0' => '',
			'W1' => "Impossible de valider votre compte !",
			'W2' => "Les données reçues ne correspondent pas au format requis !",
			'W3' => "Vous avez atteint la limite de temps pour confirmer votre compte !",
			'W4' => "Certaines données de validation sont manquantes !",
			"Keydentify - Two-Factor Authentication failed" => "Keydentify - Echec de l'authentification !"
	);

	function __($message, $id) {	
		global $i18nMessageLibs;
		
		if (isset($i18nMessageLibs['fr'][$message])) {
			$message = $i18nMessageLibs['fr'][$message];
		}
		return $message;
	}
}
?>