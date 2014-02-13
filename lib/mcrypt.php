<?php
class HKMCrypt {

	function encrypt($str, $key, $iv) {
		$td = mcrypt_module_open('rijndael-256', '', 'cbc', $iv);

		mcrypt_generic_init($td, $key, $iv);
		$encrypted = mcrypt_generic($td, $this->padString($str));

		mcrypt_generic_deinit($td);
		mcrypt_module_close($td);

		return base64_encode($encrypted);
	}

	function decrypt($code, $key, $iv) {
		$code = base64_decode($code);
		
		$td = mcrypt_module_open('rijndael-256', '', 'cbc', $iv);

		mcrypt_generic_init($td, $key, $iv);
		$decrypted = mdecrypt_generic($td, $code);

		mcrypt_generic_deinit($td);
		mcrypt_module_close($td);

		return utf8_encode(trim($decrypted));
	}
	
	protected function padString($str) {
		$block = mcrypt_get_block_size('rijndael-256', 'cbc');
		$pad = $block - (strlen($str) % $block);
		$str .= str_repeat(' ', $pad);
		return $str;
	}
}
?>