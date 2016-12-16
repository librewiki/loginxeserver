<?php
class loginxeserverView extends loginxeserver
{
	function init()
	{
		global $gConsumerSecret, $gTokenSecret;
		$this->setTemplatePath($this->module_path . 'tpl');
		$this->setTemplateFile(strtolower(str_replace('dispLoginxeserver', '', $this->act)));
	}

	function sign_request( $method, $url, $params = array() ) {
		global $gConsumerSecret, $gTokenSecret;

		$parts = parse_url( $url );

		// We need to normalize the endpoint URL
		$scheme = isset( $parts['scheme'] ) ? $parts['scheme'] : 'http';
		$host = isset( $parts['host'] ) ? $parts['host'] : '';
		$port = isset( $parts['port'] ) ? $parts['port'] : ( $scheme == 'https' ? '443' : '80' );
		$path = isset( $parts['path'] ) ? $parts['path'] : '';
		if ( ( $scheme == 'https' && $port != '443' ) ||
			( $scheme == 'http' && $port != '80' ) 
		) {
			// Only include the port if it's not the default
			$host = "$host:$port";
		}

		// Also the parameters
		$pairs = array();
		parse_str( isset( $parts['query'] ) ? $parts['query'] : '', $query );
		$query += $params;
		unset( $query['oauth_signature'] );
		if ( $query ) {
			$query = array_combine(
				// rawurlencode follows RFC 3986 since PHP 5.3
				array_map( 'rawurlencode', array_keys( $query ) ),
				array_map( 'rawurlencode', array_values( $query ) )
			);
			ksort( $query, SORT_STRING );
			foreach ( $query as $k => $v ) {
				$pairs[] = "$k=$v";
			}
		}

		$toSign = rawurlencode( strtoupper( $method ) ) . '&' .
			rawurlencode( "$scheme://$host$path" ) . '&' .
			rawurlencode( join( '&', $pairs ) );
		$key = rawurlencode( $gConsumerSecret ) . '&' . rawurlencode( $gTokenSecret );
		return base64_encode( hash_hmac( 'sha1', $toSign, $key, true ) );
	}

	function dispLoginxeserverGetServerProtocolVersion()
	{
		Context::setRequestMethod('JSON'); // 요청을 JSON 형태로
		Context::setResponseMethod('JSON'); // 응답을 JSON 형태로

		$this->add('version', $this->LOGINXE_SERVER_PROTOCOL);
	}

	function dispLoginxeserverGetAuthKey()
	{
		Context::setRequestMethod('JSON'); // 요청을 JSON 형태로
		Context::setResponseMethod('JSON'); // 응답을 JSON 형태로

		$service = Context::get('provider');
		$state = Context::get('state');
		$code = rawurldecode(Context::get('code'));

		if($code=='' || $state=='' || $service=='')
		{
			//필요한 값이 없으므로 오류
			return new Object(-1,'msg_invalid_request');
		}

		if(!$this->checkOpenSSLSupport())
		{
			return new Object(-1,'loginxesvr_need_openssl');
		}

		$oLoginXEServerModel = getModel('loginxeserver');
		$module_config = $oLoginXEServerModel->getConfig();

		if($service=='naver')
		{
			//API 서버에 code와 state값을 보내 인증키를 받아 온다
			$ping_url = 'https://nid.naver.com/oauth2.0/token?client_id=' . $module_config->clientid . '&client_secret=' . $module_config->clientkey . '&grant_type=authorization_code&state=' . $state . '&code=' . $code;
			$ping_header = array();
			$ping_header['Host'] = 'nid.naver.com';
			$ping_header['Pragma'] = 'no-cache';
			$ping_header['Accept'] = '*/*';

			$request_config = array();
			$request_config['ssl_verify_peer'] = false;

			$buff = FileHandler::getRemoteResource($ping_url, null, 10, 'GET', 'application/x-www-form-urlencoded', $ping_header, array(), array(), $request_config);
			$data= json_decode($buff);

			$token = $data->access_token;
		}
		elseif($service=='github')
		{
			//API 서버에 code와 state값을 보내 인증키를 받아 온다
			$ping_url = 'https://github.com/login/oauth/access_token';
			$ping_header = array();
			$ping_header['Host'] = 'github.com';
			$ping_header['Pragma'] = 'no-cache';
			$ping_header['Accept'] = 'application/json';

			$request_config = array();
			$request_config['ssl_verify_peer'] = false;

			$buff=FileHandler::getRemoteResource($ping_url, null, 10, 'POST', 'application/x-www-form-urlencoded', $ping_header, array(), array('client_id'=>$module_config->githubclientid,'client_secret'=>$module_config->githubclientkey,'code'=>$code), $request_config);
			$data=json_decode($buff);

			$token = $data->access_token;
		}

		$this->add('access_token', $token);
	}

	/**
	 *
	 */
	function dispLoginxeserverOAuth()
	{
		global $gConsumerSecret;
		//oauth display & redirect act
		//load config here and redirect to service
		//key check & domain check needed
		//needed value=service,id,key,state(client-generated),callback-url(urlencoded)
		$service = Context::get('provider');
		$id = Context::get('id');
		$key = Context::get('key');
		$state = htmlentities(Context::get('state'));
		$version = Context::get('version');
		//if version parameter is null, consider as version 1.0(old)
		if($version=='') $version='1.0';
		$_SESSION['loginxe_version'] = $version;
		$_SESSION['loginxe_state'] = $state;
		$callback = urldecode(Context::get('callback'));
		$domain = parse_url($callback,PHP_URL_HOST);
		$oLoginXEServerModel = getModel('loginxeserver');
		$module_config = $oLoginXEServerModel->getConfig();
		if(!in_array($domain,$module_config->loginxe_domains)) return new Object(-1,'등록된 도메인이 아닙니다.');
		$_SESSION['loginxe_callback'] = $callback;



		if($module_config->id!=$id || $module_config->key!=$key)
		{
			Context::set('url',getNotEncodedUrl('','module','loginxeserver','act','dispLoginxeserverOAuthFinish','error','1','message','msg_invalid_request'));
			return;
		}

		if($service=='naver')
		{
			if(!isset($module_config->clientid) || $module_config->clientid=='' || !isset($module_config->clientkey) || $module_config->clientkey=='')
			{
				Context::set('url',getNotEncodedUrl('','module','loginxeserver','act','dispLoginxeserverOAuthFinish','error','1','message','loginxe_not_finished_setting'));
				return;
			}

			Context::set('url','https://nid.naver.com/oauth2.0/authorize?client_id=' . $module_config->clientid . '&response_type=code&redirect_uri=' . urlencode(getNotEncodedFullUrl('','module','loginxeserver','act','dispLoginxeserverOAuthFinish','provider','naver','callback','')) . '&state=' . $state);
			return;
		}
		if($service=='mw') {
			if(!isset($module_config->clientid) || $module_config->clientid=='' || !isset($module_config->clientkey) || $module_config->clientkey=='')
                        {
                                Context::set('url',getNotEncodedUrl('','module','loginxeserver','act','dispLoginxeserverOAuthFinish','error','1','message','loginxe_not_finished_setting'));
                                return;
                        }
			$gConsumerSecret = $module_config->clientkey;

			$ping_url = 'https://librewiki.net/wiki/%ED%8A%B9%EC%88%98:MWO%EC%9D%B8%EC%A6%9D/initiate?format=json&oauth_callback=oob&oauth_consumer_key=' . $module_config->clientid . '&oauth_version=1.0&oauth_nonce=' . md5( microtime() . mt_rand() ) . '&oauth_timestamp=' . time() .'&oauth_signature_method=HMAC-SHA1&title=%ED%8A%B9%EC%88%98:MWO%EC%9D%B8%EC%A6%9D/initiate';
			$signature = $this->sign_request( 'GET', $ping_url );
			$ping_url .= "&oauth_signature=" . urlencode( $signature );

			$ping_header = array();
                        $ping_header['Host'] = 'librewiki.net';
                        $ping_header['Pragma'] = 'no-cache';
                        $ping_header['Accept'] = '*/*';

                        $request_config = array();
			$request_config['ssl_verify_peer'] = false;

                        $buff = FileHandler::getRemoteResource($ping_url, null, 10, 'GET', 'application/x-www-form-urlencoded', $ping_header, array(), array(), $request_config);
                        $data= json_decode($buff);

                        $token = $data->key;
			$secret = $data->secret;
			$_SESSION['loginxe_key'] = $token;
			$_SESSION['loginxe_secret'] = $secret;
			Context::set('url','https://librewiki.net/wiki/%ED%8A%B9%EC%88%98:MWO%EC%9D%B8%EC%A6%9D/authorize?oauth_token=' . $token . '&oauth_consumer_key=' . $module_config->clientid . '&state=' . $state);
			return;
		}
		elseif($service=='xe')
		{
			Context::set('url',getNotEncodedUrl('','module','loginxeserver','act','dispLoginxeserverOAuthFinish','error','1','message','loginxe_not_implemented'));
			return;
		}
		elseif($service=='github')
		{
			if(!isset($module_config->githubclientid) || $module_config->githubclientid=='' || !isset($module_config->githubclientkey) || $module_config->githubclientkey=='')
			{
				Context::set('url',getNotEncodedUrl('','module','loginxeserver','act','dispLoginxeserverOAuthFinish','error','1','message','loginxe_not_finished_setting'));
				return;
			}
			Context::set('url','https://github.com/login/oauth/authorize?client_id=' . $module_config->githubclientid . '&redirect_uri=' . urlencode(getNotEncodedFullUrl('','module','loginxeserver','act','dispLoginxeserverOAuthFinish','provider','github','callback','')) . '&state=' . $state . '&scope=user');
			//Context::set('url',getNotEncodedUrl('','module','loginxeserver','act','dispLoginxeserverOAuthFinish','error','1','message','loginxe_not_implemented'));

			return;
		}
		else
		{
			Context::set('url',getNotEncodedUrl('','module','loginxeserver','act','dispLoginxeserverOAuthFinish','error','1','message','loginxe_not_implemented'));
		}
	}

	function dispLoginxeserverOAuthFinish()
	{
		//proc oauth value and save
		//save with loginxeclient-publickey, generated key, statekey, oauth-key,oauth-secret
		//redirect to loginxeclient-returnurl with generated key and statekey
		$isError = Context::get('error');
		$message = Context::get('message');
		$service = Context::get('provider');
		$state = Context::get('state');
		$code = Context::get('oauth_verifier');
		$version = $_SESSION['loginxe_version'];
		$token = $_SESSION['loginxe_key'];
		$secret = $_SESSION['loginxe_secret'];
		global $gConsumerSecret, $gTokenSecret;

		if($code=='' || $state=='' || $service=='' || !isset($_SESSION['loginxe_callback']) || $_SESSION['loginxe_callback']=='' || !isset($token))
		{
			//필요한 값이 없으므로 오류
			return new Object(-1,'msg_invalid_request');
		}

		if($isError=='1')
		{
			Context::setBrowserTitle('LoginXE Server Error');
			return new Object(-1,$message);
		}

		if($isError!="") return new Object(-1, Context::get("error_description"));
		$stored_state = $_SESSION['loginxe_state'];

		//세션변수 비교(CSRF 방지)
		if( $state != $stored_state ) {
			return new Object(-1, 'loginxesvr_invalid_state');
		}

		//if client protocol version is 1.1, just return auth_token
		//client will call dispLoginxeserverGetAuthKey function to get access key
		if($version=='1.1')
		{
			Context::set('url',$_SESSION['loginxe_callback'] . '&access_token=' . urlencode($code) . '&state=' . $state);
			return;
		}

		//ssl 연결을 지원하지 않는 경우 리턴(API 연결은 반드시 https 연결이여야 함)
		//SSL 미지원시 리턴
		if(!$this->checkOpenSSLSupport())
		{
			return new Object(-1,'loginxesvr_need_openssl');
		}

		$oLoginXEServerModel = getModel('loginxeserver');
		$module_config = $oLoginXEServerModel->getConfig();

		if($service=='naver')
		{
			//API 서버에 code와 state값을 보내 인증키를 받아 온다
			$ping_url = 'https://nid.naver.com/oauth2.0/token?client_id=' . $module_config->clientid . '&client_secret=' . $module_config->clientkey . '&grant_type=authorization_code&state=' . $state . '&code=' . $code;
			$ping_header = array();
			$ping_header['Host'] = 'nid.naver.com';
			$ping_header['Pragma'] = 'no-cache';
			$ping_header['Accept'] = '*/*';

			$request_config = array();
			$request_config['ssl_verify_peer'] = false;

			$buff = FileHandler::getRemoteResource($ping_url, null, 10, 'GET', 'application/x-www-form-urlencoded', $ping_header, array(), array(), $request_config);
			$data= json_decode($buff);

			$token = $data->access_token;
		}
		if($service=='mw') {
			$gConsumerSecret = $module_config->clientkey;
			$gTokenSecret = $secret;
			
			$ping_url = 'https://librewiki.net/wiki/%ED%8A%B9%EC%88%98:MWO%EC%9D%B8%EC%A6%9D/token?format=json&oauth_verifier=' . $code . '&oauth_consumer_key=' . $module_config->clientid . '&oauth_token=' . $token . '&oauth_version=1.0&oauth_nonce=' . md5( microtime() . mt_rand() ) . '&oauth_timestamp=' . time() . '&oauth_signature_method=HMAC-SHA1&title=%ED%8A%B9%EC%88%98:MWO%EC%9D%B8%EC%A6%9D/token';
			$signature = $this->sign_request( 'GET', $ping_url );
			$ping_url .= "&oauth_signature=" . urlencode( $signature );

			$ping_header = array();
                        $ping_header['Host'] = 'librewiki.net';
                        $ping_header['Pragma'] = 'no-cache';
                        $ping_header['Accept'] = '*/*';

                        $request_config = array();
                        $request_config['ssl_verify_peer'] = false;

                        $buff = FileHandler::getRemoteResource($ping_url, null, 10, 'GET', 'application/x-www-form-urlencoded', $ping_header, array(), array(), $request_config);
                        $data= json_decode($buff);

			$token = $data->key;
			$secret = $data->secret;			

			$_SESSION['loginxe_key'] = $token;
			$_SESSION['loginxe_secret'] = $secret;

		}
		elseif($service=='github')
		{
			//API 서버에 code와 state값을 보내 인증키를 받아 온다
			$ping_url = 'https://github.com/login/oauth/access_token';
			$ping_header = array();
			$ping_header['Host'] = 'github.com';
			$ping_header['Pragma'] = 'no-cache';
			$ping_header['Accept'] = 'application/json';

			$request_config = array();
			$request_config['ssl_verify_peer'] = false;

			$buff=FileHandler::getRemoteResource($ping_url, null, 10, 'POST', 'application/x-www-form-urlencoded', $ping_header, array(), array('client_id'=>$module_config->githubclientid,'client_secret'=>$module_config->githubclientkey,'code'=>$code), $request_config);
			$data=json_decode($buff);

			$token = $data->access_token;
		}


		else
		{
			return new Object(-1, 'msg_invalid_request');
		}


		Context::set('url',$_SESSION['loginxe_callback'] . '&token=' . urlencode($token) . '&state=' . $state);
	}
}
