# encoding: utf-8
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
                      "<Content><![CDATA[%s]]></Content>"\
                      '<FuncFlag>0</FuncFlag>'\
                      '</xml>'
    
    raw_xml = decrypt(params[:xml][:Encrypt])
    new_xml = raw_xml[20..-19]
    xml = Hash.from_xml(new_xml) 
    to_user_name = xml["xml"]["FromUserName"]
    from_user_name = xml["xml"]["ToUserName"]
    text = xml["xml"]["Content"]
    time = "1432093910"
    msg = text_xml_string%[to_user_name, from_user_name, time, text] 
    #msg = "<xml><ToUserName><![CDATA[#{to_user_name}]]></ToUserName><FromUserName><![CDATA[#{from_user_name}]]></FromUserName><CreateTime>#{time}</CreateTime><MsgType><![CDATA[news]]></MsgType><ArticleCount>1</ArticleCount><Articles><item><Title><![CDATA[#{text}]]></Title><Description><![CDATA[#{text}]]></Description><PicUrl><![CDATA[http://pingtai-test.kehutong.com/image1.png]]></PicUrl><Url><![CDATA[www.baidu.com]]></Url></item></Articles></xml>"
    logger.info msg
    logger.info msg.bytesize
    encrypted = encrypt(msg.encode('utf-8'))
    timestamp = "1432093910"
    nonce = "1775384677"
    token = "moode10086"
    logger.info "--#{token}==#{nonce}#++#{timestamp}**#{encrypted}"
    signature = Digest::SHA1.hexdigest([token, nonce, timestamp, encrypted].sort.join)
    
    # "<ToUserName><![CDATA[#{to_user_name}]]></ToUserName>"\
    render_xml = '<xml>'\
		 "<Encrypt><![CDATA[#{encrypted}]]></Encrypt>"\
		 "<MsgSignature><![CDATA[#{signature}]]></MsgSignature>"\
		 "<TimeStamp>#{timestamp}</TimeStamp>"\
		 "<Nonce><![CDATA[#{nonce}]]></Nonce>"\
		 '</xml>'
    logger.info render_xml
    render xml: render_xml 
  end

  def test_oauth
    logger.info params
    code = params[:code]
    appid = params[:appid]
    a = RestClient.get("https://api.weixin.qq.com/sns/oauth2/component/access_token?appid=#{appid}&code=#{code}&grant_type=authorization_code&component_appid=#{$app_id}&component_access_token=#{$component_verify_token}")
    render json: a
  end

  #=====================================分割线==========================

  def decrypt(text)
    encoding_aes_key = $key
    aes_key = Base64.decode64("#{encoding_aes_key}=")
    aes = OpenSSL::Cipher::Cipher.new('AES-256-CBC')
    aes.decrypt
    aes.key = aes_key
    aes.iv = aes_key[0..15]
    b = aes.update(Base64.decode64(text))
    begin
      a = b + aes.final
    rescue
      a = b
    end
    logger.info a
    a
  end
  
  def encrypt(text)
    encoding_aes_key = $key
    aes_key = Base64.decode64("#{encoding_aes_key}=")
    random_string = ("a" * 16)
    msg_len = [text.bytesize].pack('N')
    logger.info "--#{aes_key.encoding}==#{msg_len.encoding}++#{text.encoding}"
    to_encrypt = random_string + msg_len + text + $app_id
    logger.info "------#{aes_key.bytesize}--------#{to_encrypt.bytesize}"
    buwei_count = aes_key.bytesize - (to_encrypt.bytesize % aes_key.bytesize)
    buwei_count = aes_key.bytesize if buwei_count == 0
    character = buwei_count.chr
    to_encrypt += character * buwei_count
    #encrypted = AESCrypt.encrypt_data(to_encrypt, aes_key, aes_key[0..15], "AES-256-CBC")
    aes = OpenSSL::Cipher::Cipher.new('AES-256-CBC')
    aes.encrypt
    aes.key = aes_key
    aes.iv = aes_key[0..15]
    encrypted = aes.update(to_encrypt)
    logger.info "_______#{Base64.encode64(encrypted + aes.final).gsub("\n", '')}_____________"
    Base64.encode64(encrypted).gsub("\n", '')
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
