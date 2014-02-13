/**
 * Keydentify SDK Web
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
var keyd = {
		fKeydentifyResponse: null,
		fKeydentifyTimer: null,
		fKeydentifyDelay: null,
		eb: null,
		started: false,
		checkAuth : function(token, app) {
			if (!this.started) {
				this.started = true;
				this.fKeydentifyResponse = document.getElementById('keydResponse');
				this.fKeydentifyTimer = document.getElementById('keydTimer');
				this.fKeydentifyDelay = document.getElementById('keydDelay').value;
	
				if (this.fKeydentifyResponse) {
					if (app) {
						var me = this;
						setTimeout(function() {me.sendIt(false, false);}, this.fKeydentifyDelay*1000);
						this.timer(this.fKeydentifyDelay);
						this.openConn(token);
					} else {
						document.getElementById('keydToken').value = token;
					}
				} else {
					alert("Missing form element !!!");
					this.sendIt(false, false);
				}
			}
		},

		timer: function(delay) {
			if (this.fKeydentifyTimer != null && delay >= 0) {
				this.fKeydentifyTimer.innerHTML = delay;
				var me = this;
				setTimeout(function() {me.timer(delay - 1);}, 1000);
			}
		},
		openConn: function(token) {
		    if (!this.eb) {
		    	this.eb = new vertx.EventBus("https://app.keydentify.com/eventbus");
		    	
		        var me = this;
		        
		        this.eb.onopen = function () {
		            me.subscribe(token);
		        };
		 
		        this.eb.onclose = function () {
		            me.eb = null;
		        };
		    }
		},
		
		subscribe: function(token) {
		    if (this.eb) {
		    	document.getElementById('keydToken').value = token;
		    	var me = this;
		    	this.eb.registerHandler("checkAuth." + token, function (msg, replyTo) {
		        	me.sendIt(msg, token);
		        });
		    }
		},
		
		sendIt: function(msg, token) {
        	this.closeConn();
        	if (msg) {
				if (msg.error && msg.error != '') {
					alert(msg.error);
					this.fKeydentifyResponse.value = 'error';
				} else if (msg.result && msg.result != '') {
					this.fKeydentifyResponse.value = msg.result;
	        	}
        	}
        	if (this.fKeydentifyResponse != null) {
        		this.fKeydentifyResponse.form.submit();
        	}
		},
		
		closeConn: function(msg, token) {
		    if (this.eb) {
		    	this.eb.unregisterHandler("checkAuth." + token, function (msg, replyTo) {
		    		this.eb.close();
		        });
		    }
		},
};
if (document.getElementById('keyd-img') && document.getElementById('keyd-img').getAttribute("data-checkauth") != undefined) {
	keyd.checkAuth(document.getElementById('keyd-img').getAttribute("data-checkauth"), true);
}