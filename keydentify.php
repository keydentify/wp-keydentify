<?php
/*
Plugin Name: Keydentify - Two-Factor Authentication
Plugin URI: http://www.keydentify.com/
Description: Allows secure user accounts with Keydentify service.
Author: Keydentify
Version: 1.0
Author URI: http://www.keydentify.com/
*/

$keydentifyVersion = '0.4';
load_plugin_textdomain("keydentify", 'wp-content/plugins/keydentify/localization');
$keydentify_html_second_step = '';

	/**
	 * Keydentify first step authentication
	 * If the entered login / password are ok, and the user need (or wants) to use Keydentify, process to the second step
	 *
	 * @param string $user 
	 * @param string $username 
	 * @param string $password 
	 * @return Results of autheticating via wp_authenticate_username_password(), using the username found when looking up via email.
	 */
	function keydentify_check_login( $user, $username, $password ) {
		global $keydentify_html_second_step;
		
		require_once("lib/keydentifyAPI.php");
		
		remove_action('authenticate', 'wp_authenticate_username_password', 20);
	
		$service_id = esc_attr(keydentify_get_option('keydentify_wid'));
		$secretKey = esc_attr(keydentify_get_option('keydentify_skey'));
		$authtype = esc_attr(keydentify_get_option('keydentify_authtype'));
				
		if (isset($_POST['keydResponse']) && (!isset($_POST['keydentify']) || $_POST['keydentify'] == "1")) {

			# User have been authenticated by Keydentify ?
			$user = get_user_by('login', esc_attr($_POST['login']));
			$check = KeydentifyAPI::checkKeydentifyResponse($service_id, $user->id, $secretKey, $_POST);
			if (!is_bool($check)) {
				$user = new WP_Error('Keydentify authentication failed', __("Keydentify - Two-Factor Authentication failed", "keydentify")." : ".$check);
			} else if (isset($_POST['keydentify']) && $_POST['keydentify'] == "1") {
				# The user has just activated Keydentify ?
				keydentify_user_login_save($user->id, true);
			}
			
			return $user;
		}
		
		if (isset($_POST['keydentify']) && $_POST['keydentify'] == "2") {
			$user = get_user_by('login', esc_attr($_POST['login']));
			$check = KeydentifyAPI::checkKeydentifyPost($service_id, $user->id, $secretKey, $_POST);
			
			if (!is_bool($check)) {
				$user = new WP_Error('Keydentify authentication failed', __("Keydentify - Two-Factor Authentication failed", "keydentify"));
			} else {
				keydentify_user_login_save($user->id, true);
				return $user;
			}
		} 
		
		
		# Check if the credentials are goods but do not authenticate user ...
		$user = wp_authenticate_username_password(null, $username, $password);
		
		# Is user using Keydentify ?
		$useKeydentify = get_the_author_meta( 'keydentify', $user->id );

		if (!is_a($user, 'WP_User')) { //true || 
			# no account for this credentials, stop here ...
			return $user;
		} else {
			
			if (defined('XMLRPC_REQUEST') && XMLRPC_REQUEST) {
				return $user;
			} else if ($useKeydentify != "1") {
				
				if ($useKeydentify == null || $useKeydentify == '') {

					# Ask the user if he want to use Keydentify
					remove_action( 'login_form', 'keydentify_login_form_first_step', 2 );
					add_action( 'login_head', 'keydentify_login_head_second_step');
					if ($authtype == "1") {
						$requestAuth = KeydentifyAPI::requestAuth(esc_attr($service_id), esc_attr($user->id), $secretKey, esc_attr($username), get_locale(), esc_attr($_POST['redirect_to']), $_SERVER['REMOTE_ADDR'], $authtype, esc_attr($user->user_email), $user->keydentify_phone_number);
						
						if (is_null($requestAuth) || !$requestAuth || !is_array($requestAuth)) {
							return $user;
						} else {
							$keydentify_html_second_step = $requestAuth['html'];
						}
					} else {
						$keydentify_html_second_step = KeydentifyAPI::buildFormFields(null, $authType, esc_attr($service_id), esc_attr($user->id), $secretKey, esc_attr($_POST['redirect_to']), esc_attr($username));
					}
					
					$keydentify_html_second_step .= keydentify_user_selector_login_choice($user);
					
					add_action( 'login_footer', 'keydentify_login_form_second_step');
					do_action( 'login_head' );
					
				} else {
					return $user;
				}
			} else {
				
				remove_action( 'login_form', 'keydentify_login_form_first_step', 2 );
				add_action( 'login_head', 'keydentify_login_head_second_step');				

				$requestAuth = KeydentifyAPI::requestAuth(esc_attr($service_id), esc_attr($user->id), $secretKey, esc_attr($username), get_locale(), esc_attr($_POST['redirect_to']), $_SERVER['REMOTE_ADDR'], $authtype, esc_attr($user->user_email), esc_attr($user->keydentify_phone_number));
				if (is_null($requestAuth) || !$requestAuth || !is_array($requestAuth)) {
					return $user;
				} else {
					$keydentify_html_second_step = $requestAuth['html'];
				}
				
				add_action( 'login_footer', 'keydentify_login_form_second_step');
				do_action( 'login_head' );
			}
		}
	}
	add_filter( 'authenticate', 'keydentify_check_login', 10, 3 );
	
	function keydentify_settings_page() {
		?>
	    <div class="wrap">
	        <h2>Keydentify - Two-Factor Authentication</h2>
	        <?php if(is_multisite()) { ?>
	            <form action="ms-options.php" method="post">
	        <?php } else { ?>
	            <form action="options.php" method="post"> 
	        <?php } ?>
	            <?php settings_fields('keydentify_settings'); ?>
	            <?php do_settings_sections('keydentify_settings'); ?> 
	            <p class="submit">
	                <input name="Submit" type="submit" value="<?php esc_attr_e('Save Changes'); ?>" />
	            </p>
	        </form>
	    </div>
	<?php
    }

    function keydentify_settings_wid() {
        $wid = esc_attr(keydentify_get_option('keydentify_wid'));
        echo "<input id='keydentify_wid' name='keydentify_wid' size='50' type='text' value='$wid' />";
    }

    function keydentify_settings_skey() {
        $skey = esc_attr(keydentify_get_option('keydentify_skey'));
        echo "<input id='keydentify_skey' name='keydentify_skey' size='50' type='text' value='$skey' />";
    }
    
    function keydentify_settings_authtype() {
    	$authtype = esc_attr(keydentify_get_option('keydentify_authtype'));
    	echo '<select name="keydentify_authtype" id="keydentify_authtype" class="regular-text" />';
    	echo '	<option value="1" '. (($authtype == "1") ? 'selected="selected"' : '') .'>'. __('With Keydentify app', "keydentify").'</option>';
    	echo '	<option value="2" '. (($authtype == "2") ? 'selected="selected"' : '') .'>'. __('3D Secure by SMS', "keydentify").'</option>';
    	echo '	<option value="3" '. (($authtype == "3") ? 'selected="selected"' : '') .'>'. __('3D Secure by Phone Call', "keydentify").'</option>';
    	echo '</select>';
    }

    function keydentify_settings_text() {
        echo __("<p>To enable Keydentify two-factor authentication for your WordPress login, you need to configure your integration settings (retrieve your integration key and secret key on your <a target='_blank' href='https://www.keydentify.me'>dedicated Keydentify console</a>).</p>", "keydentify");
        echo __("<p>If you don't yet have a Keydentify account, sign up now for free at <a target='_blank' href='http://www.keydentify.com'>http://www.keydentify.com</a>.</p>", "keydentify");
    }

    function keydentify_settings_wid_validate($wid) {
        if (strlen($wid) != 24) {
            add_settings_error('keydentify_wid', '', __("Service ID is not valid", "keydentify"));
            return "";
        } else {
            return $wid;
        }
    }
    
    function keydentify_settings_skey_validate($skey){
        if (strlen($skey) != 48) {
            add_settings_error('keydentify_skey', '', __("Secret key is not valid", "keydentify"));
            return "";
        } else {
            return $skey;
        }
    }
    
    function keydentify_settings_authtype_validate($authtype){
    	if (strlen($authtype) != 1 || !($authtype >= 0 && $authtype <=3)) {
    		add_settings_error('keydentify_authtype', '', __("Auth Type is not valid", "keydentify"));
    		return "";
    	} else {
    		return $authtype;
    	}
    }

    function keydentify_admin_init() {
        if (is_multisite()) {
            add_site_option('keydentify_wid', '');
            add_site_option('keydentify_skey', '');
            add_site_option('keydentify_authtype', '');
        }
        else {
            add_settings_section('keydentify_settings', __('Main Settings', "keydentify"), 'keydentify_settings_text', 'keydentify_settings');
            add_settings_field('keydentify_', __('Service Id', "keydentify"), 'keydentify_settings_wid', 'keydentify_settings', 'keydentify_settings');
            add_settings_field('keydentify_skey', __('Secret key', "keydentify"), 'keydentify_settings_skey', 'keydentify_settings', 'keydentify_settings');
            add_settings_field('keydentify_authtype', __('Auth Type', "keydentify"), 'keydentify_settings_authtype', 'keydentify_settings', 'keydentify_settings');
            register_setting('keydentify_settings', 'keydentify_wid', 'keydentify_settings_wid_validate');
            register_setting('keydentify_settings', 'keydentify_skey', 'keydentify_settings_skey_validate');
            register_setting('keydentify_settings', 'keydentify_authtype', 'keydentify_settings_authtype_validate');
        }

    }

    function keydentify_settings_mu_options() { ?>
        <h3>Keydentify - Two-Factor Authentication</h3>
        <table class="form-table">
            <?php keydentify_settings_text();?></td></tr>
            <tr><th><?php _e("Service Id", "keydentify"); ?></th><td><?php keydentify_settings_wid();?></td></tr>
            <tr><th><?php _e("Secret key", "keydentify"); ?></th><td><?php keydentify_settings_skey();?></td></tr>
            <tr><th><?php _e("Auth Type", "keydentify"); ?></th><td><?php keydentify_settings_authtype();?></td></tr>
        </table>
	<?php
    }

    function keydentify_settings_update_mu_options() {
        if(isset($_POST['keydentify_wid'])) {
            $wid = $_POST['keydentify_wid'];
            $result = update_site_option('keydentify_wid', $wid);
        }

        if(isset($_POST['keydentify_skey'])) {
            $skey = $_POST['keydentify_skey'];
            $result = update_site_option('keydentify_skey', $skey);
        }
        
        if(isset($_POST['keydentify_authtype'])) {
        	$authtype = $_POST['keydentify_authtype'];
        	$result = update_site_option('keydentify_authtype', $authtype);
        }
    }

    function keydentify_add_page() {
        if(! is_multisite()) {
            add_options_page('Keydentify', 'Keydentify', 'manage_options', 'keydentify', 'keydentify_settings_page');
        }
    }

    function keydentify_add_link($links, $file) {
        static $this_plugin;
        if (!$this_plugin) $this_plugin = plugin_basename(__FILE__);

        if ($file == $this_plugin) {
            $settings_link = '<a href="options-general.php?page=keydentify">'.__("Settings", "keydentify").'</a>';
            array_unshift($links, $settings_link);
        }
        return $links;
    }

    /*-------------Register WordPress Hooks-------------*/
    add_action( 'login_form', 'keydentify_login_form_first_step', 2 );
    add_filter('plugin_action_links', 'keydentify_add_link', 10, 2 );
    
    if(is_multisite() && is_network_admin()){
        add_action('network_admin_menu', 'keydentify_add_page');
        
        # Custom fields in network settings
        add_filter('wpmu_options', 'keydentify_settings_mu_options');
        add_filter('update_wpmu_options', 'keydentify_settings_update_mu_options');
    }
    else {
        add_action('admin_menu', 'keydentify_add_page');
    }
    
    add_action('admin_init', 'keydentify_admin_init');

    function keydentify_get_option($key, $default="") {
        if (is_multisite()) {
            return get_site_option($key, $default);
        } else {
            return get_option($key, $default);
        }
    }

    # USER PROFILE KEYDENTIFY SELECTOR
    add_action( 'show_user_profile', 'keydentify_user_selector_profile' );
    add_action( 'edit_user_profile', 'keydentify_user_selector_profile' );
    
    function keydentify_user_selector_profile($user) {
		$keydentifySelector = get_the_author_meta( 'keydentify', $user->id );
		$keydentifyPhoneNumber = get_the_author_meta( 'keydentify_phone_number', $user->id );
		$authtype = esc_attr(keydentify_get_option('keydentify_authtype'));
	?>
	<script>
	function phoneNumberVisibility(activated) {
		if (<?php ($authtype == "1") ? 'false && ' : ''; ?>activated == 1) {
			document.getElementById("tr_keydentify_phone_number").style.display = '';
		} else {
			document.getElementById("tr_keydentify_phone_number").style.display = 'none';
		}
	}
	</script>
	<h3><?php _e('Security', "keydentify"); ?></h3>
    	<table class="form-table">
    		<tr>
    			<th><label for="keydentify">Keydentify - Two-Factor Authentication</label></th>
    			<td>
			    	<span class="description">
				    	<select name="keydentify" id="keydentify" class="regular-text" onchange="phoneNumberVisibility(this.value);" />
				    		<option value="1" <?php if ($keydentifySelector == "1") {echo 'selected="selected"';} ?>><?php _e('Yes, secure my account with Keydentify', "keydentify"); ?></option>
				    		<option value="2" <?php if ($keydentifySelector == "2") {echo 'selected="selected"';} ?>><?php _e("I don't want to use Keydentify for now", "keydentify"); ?></option>
				    	</select>
				    	<?php _e('Do you want to activate Keydentify - Two-Factor Authentication ?', "keydentify"); ?>
			    	</span>
    			</td>
    		</tr>
    		<tr id="tr_keydentify_phone_number" <?php if ($authtype == "1" || $keydentifySelector == "2") { echo ' style="display:none;"'; } ?>>
    			<th></th>
    			<td>
			    	<span class="description">
			    		<input type="tel" value="<?php echo $keydentifyPhoneNumber; ?>" name="keydentify_phone_number" id="keydentify_phone_number">
			    		<?php _e('Please enter your mobile phone number', "keydentify"); ?>
			    	</span>
    			</td>
    		</tr>
    	</table>
    <?php 
	}
    
	function keydentify_user_selector_login_choice($user) {
		$keydentifySelector = get_the_author_meta( 'keydentify', $user->id );
		$authtype = esc_attr(keydentify_get_option('keydentify_authtype'));
		
		if (is_multisite()) {
			global $blog_id;
			$current_blog_details = get_blog_details( array( 'blog_id' => $blog_id ) );
			$blogName = $current_blog_details->blogname;
		} else {
			$blogName = get_bloginfo();
		}		
		
		ob_start();
		?>
		<div id='presentkeydentify'>
		<p><b><?php echo $blogName.' '.__("offers secure access to your account via <a href='http://www.keydentify.com' target='_blank'>Keydentify strong authentication system</a>.", "keydentify"); ?></b><br /></p>
		<?php if ($authtype == "1") { ?>
			<p class="description"><?php echo '<br />'.__('The login process will take place in two steps:<br />1 - Enter your credentials as usually,<br />2 - Then simply launch <a href= \"http://www.keydentify.com/download/\" target=\"_blank\" title=\"Click here to download Keydentify App\">Keydentify App</a> and your identity will be confirmed.', "keydentify"); ?></p>
		<?php } else { ?>
			<p class="description"><?php echo '<br />'.__('The login process will take place in two steps:<br />1 - Enter your credentials as usually,<br />2 - Enter the security code received by SMS.', "keydentify"); ?></p>
		<?php } ?>
	    	<p><?php echo '<br />'.__('Do you want to activate this security ?', "keydentify"); ?></p>
			<div><br /><p class="submit">
				<?php 
				$submit = 'this.form.submit();';
				if ($authtype == "1") { 
					$submit = 'keyd.sendIt();'; ?>
					<input type="button" value="<?php echo __("Yes, secure my account", "keydentify"); ?>" onclick="document.getElementById('presentkeydentify').style.display='none';document.getElementById('displaykeydentify').style.display='block';" class="button button-primary button-large" id="wp-submit" name="wp-submit">
				<?php } else { ?>
					<input type="button" value="<?php echo __("Yes, secure my account", "keydentify"); ?>" onclick="<?php echo $submit; ?>" class="button button-primary button-large" id="wp-submit" name="wp-submit">
				<?php } ?>

				<input type="button" value="<?php echo __("No later", "keydentify"); ?>" onclick="document.getElementById('keydentify').value=2; <?php echo $submit; ?>" class="button button-secondary button-large" id="wp-submit" name="wp-submit">
			</p></div>
		</div>
		<input type="hidden" id="keydentify" name="keydentify" value="1">
		<?php
		return str_replace(array("\r", "\n"), "", ob_get_clean());
	}
	
	function keydentify_user_selector_save( &$errors, $update, &$user ) {
		if($update) {
			$authtype = esc_attr(keydentify_get_option('keydentify_authtype'));
			$error = false;
			# do the error handling here
			if($_POST['keydentify'] == "1" && $authtype == "2" && strlen($_POST['keydentify_phone_number']) < 6) {
				$errors->add('keydentify_phone_number', __( '<strong>ERROR</strong>: To enable Keydentify, you have to enter a valid mobile phone number.' )); //, array('form-field' => 'job')
				$error = true;
			} else if($_POST['keydentify'] != "1" || $authtype == "1") {
				$_POST['keydentify_phone_number'] = '';
			}
			
			if (!$error) {
				# no error, let's save it here
				update_user_meta($user->ID, 'keydentify', $_POST['keydentify'] );
				update_user_meta($user->ID, 'keydentify_phone_number', $_POST['keydentify_phone_number'] );
			}
		}
	}
	add_action('user_profile_update_errors', 'keydentify_user_selector_save', 10, 3);

	function keydentify_user_login_save( $user_id, $isConnected = true ) {
		/*if ($isConnected && !current_user_can( 'edit_user', $user_id ) ) {
			return false;
		}*/
		update_usermeta( $user_id, 'keydentify', $_POST['keydentify'] );
	}
	
	function keydentify_login_form_first_step() { ?>
	    <!-- Website secure by Keydentify - Two-Factor Authentication http://www.keydentify.com -->
	    <div id="keydentify_info">
	    	<p><label><b><?php echo __("Login secure by <a href='http://www.keydentify.com' target='_blank'>Keydentify</a>", "keydentify").'</b>'.__("<br />Your mobile phone is required!", "keydentify") ?></label></p><br />
	    </div>
	    <!-- /Keydentify - Two-Factor Authentication -->
	<?php }
	
	function keydentify_login_form_second_step() {
		global $keydentify_html_second_step;
		?>
	    <!-- Website secure by Keydentify - Two-Factor Authentication http://www.keydentify.com -->
	    <script type="text/javascript">
		document.getElementById('loginform').innerHTML = '<?php echo str_replace("'", "\'", $keydentify_html_second_step); ?>';
		document.getElementById('login_error').innerHTML = '';
		</script>
	    <!-- /Keydentify - Two-Factor Authentication -->
	<?php }
	
	function keydentify_login_head_second_step() {
		global $keydentifyVersion;
		$keydentify_url = WP_PLUGIN_URL.'/keydentify';
		$keydentify_local_style_path = $keydentify_url.'/css';
		$keydentify_local_script_path = $keydentify_url.'/js';
		
		wp_register_style('keydentify.css', $keydentify_local_style_path . '/keydentify.css', array(), $keydentifyVersion);
		wp_enqueue_style( 'keydentify.css');
		
		//wp_enqueue_script('keydentify-min.js', $keydentify_local_script_path . '/keydentify-min.js', array(), $keydentifyVersion, false);		
		wp_enqueue_script('sockjs', 'http://cdn.sockjs.org/sockjs-0.3.4.min.js', array(), $keydentifyVersion, false);
		wp_enqueue_script('vertxbus', $keydentify_local_script_path . '/vertxbus.js', array('sockjs'), $keydentifyVersion, false);
		wp_enqueue_script('keydentify.js', $keydentify_local_script_path . '/keydentify.js', array('vertxbus'), $keydentifyVersion, false);
		
	}
?>
