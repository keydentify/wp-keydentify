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
require_once("keydentifylib.php");

class KeydentifyAPI extends KeydentifyLib {

	public static function requestAuth($serviceId, $serviceUserId, $secretKey, $login = '', $locale = 'en', $redirectTo = '', $serviceUserIp = '', $authType = 1, $email = null, $phoneNumber = null) {
		$output = false;

		// Check data
		if (is_null($authType) || !in_array(intval($authType), array(1, 2, 3))) {
			return 'Keydentify - Auth Type must be equal to 1 (with Keydentify app) or 2 (3D Secure by SMS) or 3 (3D Secure by Phone Call)';
		} else if ($authType >= 2 && (is_null($phoneNumber) || strlen($phoneNumber) < 6)) {
			return 'Keydentify - A valid phone number is required to authenticate by SMS';
		}


		if (is_null($serviceId) || strlen($serviceId) != 24) {
			return 'Keydentify - Service id must have 24 length chars';
		}

		if (is_null($serviceUserId) || $serviceUserId == '') {
			return 'Keydentify - User Id must be filled';
		}

		// Generate challenge
		$algorithm = 'sha1';
		$salt = KeydentifyAPI::buildRandomKey(64);
		$nbrIterations = rand(16, 256);
		
		// Request fingerprint
		$sha256 = sha256($authType.$serviceId.$serviceUserId.$algorithm.$salt.$nbrIterations.sha256($secretKey).$serviceUserIp.$login.$email.$phoneNumber);
		
		// Encode these data as they may contains url specific characters
		$serviceUserId = urlencode($serviceUserId);
		$phoneNumber = urlencode($phoneNumber);
		
		$post_fields = array('auth_type' => $authType, 'service_id' => $serviceId, 'service_user_id' => $serviceUserId,
							 'service_algorithm' => $algorithm, 'service_salt' => urlencode($salt), 'service_iterations' => $nbrIterations, 'service_sha256' => $sha256,
							 'service_user_login' => $login, 'service_user_ip' => $serviceUserIp, 'service_user_locale' => $locale, 'service_user_email' => $email,
							 'service_user_phone_number' => $phoneNumber
							);
		$keydResponse = KeydentifyAPI::postData(KEYDENTIFY_SERVER . '/requestAuth', $post_fields);
		
		if ($keydResponse) {
			$keydResponseDecoded = json_decode($keydResponse, true);

			if (!is_null($keydResponseDecoded) && isset($keydResponseDecoded['infoEndAuth'])) {
				return $keydResponseDecoded['infoEndAuth'];
			}

			if (is_null($keydResponseDecoded) || !isset($keydResponseDecoded['token'])) {
				return $keydResponse;
			}

			$keydResponseDecoded['challenge'] = $algorithm.':'.$nbrIterations.':'.$salt;
			if (!isset($keydResponseDecoded['delay'])) {
				$keydResponseDecoded['delay'] = 60;
			}
			
			// Image to insert ?
			if (isset($keydResponseDecoded['message']) && isset($keydResponseDecoded['image_src_b64'])) {
				$keydResponseDecoded['message'] = str_replace("##image_src_b64##", $keydResponseDecoded['image_src_b64'], $keydResponseDecoded['message']);
			}
			
			return array('html' =>
					(isset($keydResponseDecoded['message']) ? $keydResponseDecoded['message'] : '') .
					KeydentifyAPI::buildFormFields($keydResponseDecoded, $authType, $serviceId, $serviceUserId, $secretKey, $redirectTo, $login));
		}

		return null;
	}

	public static function checkKeydentifyResponse($serviceId, $serviceUserId, $secretKey, $postData) {

		$message = 'W0';
		$messageLibs = array(
				'W0' => '',
				'W1' => __("Unable to validate your account!", "keydentify"),
				'W2' => __("The submitted data is not properly formatted!", "keydentify"),
				'W3' => __("You've have not confirmed your account in the expected time frame!", "keydentify"),
				'W4' => __("Some validation data are missing!", "keydentify")
		);
		
		if (isset($postData['keydResponse']) && $postData['keydResponse'] != '') {

			$postIntegrity = KeydentifyAPI::checkKeydentifyPost($serviceId, $serviceUserId, $secretKey, $postData);

			if (is_bool($postIntegrity) && $postIntegrity) {
				if ($postData['keydAuthType'] == "1") {
					$postData['keydChallenge'] = KeydentifyAPI::decryptChallenge($serviceId.$serviceUserId, $postData['keydChallenge']);
					list($algorithm, $count, $salt) = explode(":", $postData['keydChallenge']);
					
					if ($postData['keydResponse'] != KeydentifyAPI::pbkdf2($serviceId.$serviceUserId.$secretKey, $salt, $count, $algorithm)) {
						$message = 'W1';
					}
				} else {
					$sha256 = sha256($postData['keydToken'].$serviceId.$serviceUserId.$postData['keydAuthType']);
					$post_fields = array('auth_type' => $postData['keydAuthType'], 'token' => $postData['keydToken'],
										 'service_id' => $serviceId, 'service_user_id' => $serviceUserId, 'service_sha256' => $sha256);
					$output = KeydentifyAPI::postData(KEYDENTIFY_SERVER . '/authConfirm', $post_fields);
				}
			} else {
				$message = $postIntegrity;
			}
		} else {
			$message = 'W3';
		}
		
		if ($message != 'W0') {
			
			if ($postData['keydResponse'] != 'error') {
				$sha256 = sha256($postData['keydToken'].$serviceId.$serviceUserId.$postData['keydAuthType'].$message);
				$post_fields = array('auth_type' => $postData['keydAuthType'], 'token' => $postData['keydToken'],
									 'service_id' => $serviceId, 'service_user_id' => $serviceUserId,
									 'error' => $message, 'service_sha256' => $sha256);
				$output = KeydentifyAPI::postData(KEYDENTIFY_SERVER . '/authFailed', $post_fields);
			}
			return $messageLibs[$message];
		} else {
			return true;
		}
	}

	public static function checkKeydentifyPost($serviceId, $serviceUserId, $secretKey, $postData) {
		$message = true;

		if (isset($postData['keydTimeout']) && $postData['keydTimeout'] != ''
				&& isset($postData['keydDelay']) && $postData['keydDelay'] != ''
						&& isset($postData['keydToken']) //&& $postData['keydToken'] != ''
								&& isset($postData['keydCSRF']) && $postData['keydCSRF'] != ''
										&& isset($postData['keydChallenge']) && $postData['keydChallenge'] != '') {

			if ($postData['keydTimeout'] > time()) {
				# Check data integrity
				if ($postData['keydAuthType'] == "1") {
					if ($postData['keydCSRF'] != KeydentifyAPI::buildCSRF($postData['keydAuthType'], $secretKey, $postData['keydTimeout'], $postData['keydDelay'], $postData['keydToken'], $postData['keydChallenge'], $serviceId, $serviceUserId, $postData['redirect_to'], $postData['login'])) {
						$message = 'W2';
					}
				} else {
					if ($postData['keydCSRF'] != KeydentifyAPI::buildCSRF($postData['keydAuthType'], $secretKey, $postData['keydTimeout'], $postData['keydDelay'], $postData['keydToken'], $postData['keydChallenge'], $serviceId, $serviceUserId, $postData['redirect_to'], $postData['login'], $postData['keydResponse'])) {
						if ($postData['keydResponse'] != '') {
							$message = 'W1';
						} else {
							$message = 'W2';
						}
					}
				}
			} else {
				$message = 'W3';
			}
		} else {
			$message = 'W4';
		}

		return $message;
	}


	public static function buildFormFields($keydResponse, $authType, $serviceId, $serviceUserId, $secretKey, $redirectTo, $login) {
		
		if ($keydResponse == null) {
			$keydResponse['challenge'] = $keydResponse['token'] = $keydResponse['3DSecureCode'] = "";
			$keydResponse['delay'] = 60;
		}
		
		$keydResponse['challenge'] = KeydentifyAPI::encryptChallenge($serviceId.$serviceUserId, $keydResponse['challenge']);
		$timeOut = time() + $keydResponse['delay'];

		$html = '';
		if ($authType == 1) {
			$html = '<input type="hidden" name="keydResponse" id="keydResponse" />';
			$csrf = KeydentifyAPI::buildCSRF($authType, $secretKey, $timeOut, $keydResponse['delay'], $keydResponse['token'], $keydResponse['challenge'], $serviceId, $serviceUserId, $redirectTo, $login);
		} else {
			$csrf = KeydentifyAPI::buildCSRF($authType, $secretKey, $timeOut, $keydResponse['delay'], $keydResponse['token'], $keydResponse['challenge'], $serviceId, $serviceUserId, $redirectTo, $login, $keydResponse['3DSecureCode']);
		}

		$html .= '<input type="hidden" name="keydAuthType" id="keydAuthType" value="'.$authType.'" />' .
				'<input type="hidden" name="keydToken" id="keydToken" />' .
				'<input type="hidden" name="keydChallenge" value="'.$keydResponse['challenge'].'"/>' .
				'<input type="hidden" name="keydTimeout" id="keydTimeout" value="'.$timeOut.'"/>' .
				'<input type="hidden" name="keydDelay" id="keydDelay" value="'.$keydResponse['delay'].'"/>' .
				'<input type="hidden" name="redirect_to" id="redirect_to" value="'.$redirectTo.'"/>' .
				'<input type="hidden" name="login" id="login" value="'.$login.'"/>';

		return $html . '<input type="hidden" name="keydCSRF" value="'.$csrf.'"/>'; //, $extraCSRF
	}
}
?>