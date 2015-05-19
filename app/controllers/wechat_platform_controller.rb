class WechatPlatformController < ApplicationController

  def handle_system_event
    raw_xml = decrypt(params[:xml][:Encrypt])
    new_xml = raw_xml[20..-19]
    xml = Hash.from_xml(new_xml) 
    $component_verify_ticket = xml["xml"]["ComponentVerifyTicket"]
    logger.info '-----------handle system event------------'
    logger.info xml
    logger.info '***' * 30
    logger.info $component_verify_ticket
    logger.info '***' * 30
    render text: 'success'
  end

  def get_component_verify_token
    raw = get_component_verify_ticket($app_id, $app_secret, $component_verify_ticket)
    $component_verify_token = MultiJson.load(raw, symbolize_keys: true)[:component_access_token]    
    render json: raw
  end

  def first_step
    raw = get_preauthcode
    logger.info "***********#{raw}**********"
    @preauthcode = MultiJson.load(raw, symbolize_keys: true)[:pre_auth_code]
    @auth_url = "https://mp.weixin.qq.com/cgi-bin/componentloginpage?component_appid=#{$app_id}&pre_auth_code=#{@preauthcode}&redirect_uri=http://pingtai-test.kehutong.com/wechat_platform"
  end

  def set_ticket
    $component_verify_ticket = params[:ticket]
    render text: 'ok'
  end

  def finish
    auth_code = params[:auth_code]
    authorization_info = MultiJson.load(api_query_auth(auth_code), symbolize_keys: true)[:authorization_info]
    old_user = User.find_by(appid: authorization_info[:authorizer_appid])
    old_user.delete if old_user.present?
    user = User.create(appid: authorization_info[:authorizer_appid], access_token: authorization_info[:authorizer_access_token], refresh_token: authorization_info[:authorizer_refresh_token])
    render json: authorization_info 
  end

  def show_user_info
    user = User.find(params[:id])
    user_info = api_get_authorizer_info(user.appid)
    render json: user_info
  end

  def refresh_user_access_token
    user = User.find(params[:id])
    authorizer_token = MultiJson.load(api_authorizer_token(user.appid, user.refresh_token), symbolize_keys: true)
    user.update(access_token: authorizer_token[:authorizer_access_token])
    render json: user
  end

  def post_text_to_wechat
    to_user_openid = params[:open_id]
    text = params[:text]
    user = User.find(params[:id])
    raw = RestClient.post("https://api.weixin.qq.com/cgi-bin/message/custom/send?access_token=#{user.access_token}", {touser: to_user_openid, msgtype: 'text', text: {content: text}}.to_json)
    logger.info raw
    render json: raw
  end

  def handle_wechat_message
    text_xml_string = '<xml>'\
                      '<ToUserName><![CDATA[%s]]></ToUserName>'\
                      '<FromUserName><![CDATA[%s]]></FromUserName>'\
                      '<CreateTime>%s</CreateTime>'\
                      '<MsgType><![CDATA[text]]></MsgType>'\
                      '<Content><![CDATA[nihao]]></Content>'\
                      '<FuncFlag>0</FuncFlag>'\
                      '</xml>'
    
    raw_xml = decrypt(params[:xml][:Encrypt])
    new_xml = raw_xml[20..-19]
    xml = Hash.from_xml(new_xml) 
    to_user_name = xml["xml"]["FromUserName"]
    from_user_name = xml["xml"]["ToUserName"]
    time = Time.now.to_i
    msg = text_xml_string%[to_user_name, from_user_name, time] 
    logger.info msg
    encrypted = encrypt(msg)
    decrypt(encrypted)
    
    render_xml = '<xml>'\
		 "<ToUserName><![CDATA[#{to_user_name}]]></ToUserName>"\
		 "<Encrypt><![CDATA[#{encrypted}]]></Encrypt>"\
		 '</xml>'
    logger.info render_xml
    asd = "<xml>
<ToUserName><![CDATA[o9L_UjvOsVwTuxNZSVbIKkTfXXRI]]></ToUserName>
<Encrypt><![CDATA[gDhLt7VO7hpiT6C7jrWGDhgnysLPEjSA6qhWihLlsEzOfZzmKx8zOtiBtUUrjN/gn4FfIj7VNOVeWWCz9pCQbNPfLfF+fNf6pZBIYyckjXzt7eRhnoAdtjRAM/R18Y+bzWwDpCPSltkCdYpUACZf8tMrTXvEVFq3sKRRW2WAZqzWdNd06xpyRYY8A7XDRDDPrfYDErwWPRgHZ2ZHYOPZ6hnvc9c1c+yWYT3LggnCTgLcLHh/fDLkrktduBa39dLuijHHBBIYeDt1CFx9igD6fsTH5ahHzo1+sT68bjyK9hNCQytwdacw7rOtpU/LNwIkBe8IAkF3Ul+WBhxKr2S4zpzjgwZHF9DCJ6o8Joyq4vuxsO/ubeDFshEbMZ5Ko8zDVyXrhIrEZMxeqVPE9uvoEJS/BP2xf/HbyV+LTmf2QZY=]]></Encrypt>
<MsgSignature><![CDATA[c098858f26451cc90d907dfc5abbbdb1a820f85f]]></MsgSignature>
<TimeStamp>1432026751</TimeStamp>
<Nonce><![CDATA[1939177440]]></Nonce>
</xml>"
    render xml: asd 
  end

  #=====================================分割线==========================

  def decrypt(text)
    encoding_aes_key = $key
    aes_key = Base64.decode64("#{encoding_aes_key}=")
    a = AESCrypt.decrypt_data(Base64.decode64(text), aes_key, aes_key[0..15], "AES-256-CBC")
    logger.info a
    a
  end
  
  def encrypt(text)
    encoding_aes_key = $key
    aes_key = Base64.decode64("#{encoding_aes_key}=")
    random_string = "a" * 16
    msg_len = [text.length].pack('N')
    to_encrypt = random_string + msg_len + text + $app_id
    logger.info "------#{aes_key.length}--------#{to_encrypt.length}"
    buwei_count = aes_key.length - (to_encrypt.length % aes_key.length)
    buwei_count = aes_key.length if buwei_count == 0
    character = buwei_count.chr
    to_encrypt += character * buwei_count
    logger.info to_encrypt
    encrypted = AESCrypt.encrypt_data(to_encrypt, aes_key, aes_key[0..15], "AES-256-CBC")
    Base64.encode64(encrypted)
  end

  def get_component_verify_ticket(component_appid, component_appsecret, component_verify_ticket)
    RestClient.post("https://api.weixin.qq.com/cgi-bin/component/api_component_token", {"component_appid" => component_appid, "component_appsecret" => component_appsecret , "component_verify_ticket" => component_verify_ticket }.to_json)
  end

  def get_preauthcode
    RestClient.post("https://api.weixin.qq.com/cgi-bin/component/api_create_preauthcode?component_access_token=#{$component_verify_token}", {component_appid: $app_id}.to_json)
  end

  def api_query_auth(auth_code)
    raw = RestClient.post("https://api.weixin.qq.com/cgi-bin/component/api_query_auth?component_access_token=#{$component_verify_token}", {component_appid: $app_id, authorization_code: auth_code}.to_json)
    logger.info raw
    raw
  end

  def api_authorizer_token(auth_app_id, refresh_token)
    raw = RestClient.post("https://api.weixin.qq.com/cgi-bin/component/api_authorizer_token?component_access_token=#{$component_verify_token}", {component_appid: $app_id, authorizer_appid: auth_app_id, authorizer_refresh_token: refresh_token}.to_json)
    logger.info raw
    raw
  end

  def api_get_authorizer_info(auth_appid)
    raw = RestClient.post("https://api.weixin.qq.com/cgi-bin/component/api_get_authorizer_info?component_access_token=#{$component_verify_token}", {component_appid: $app_id, authorizer_appid: auth_appid}.to_json)
    logger.info raw
    raw
  end

end
