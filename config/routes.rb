Rails.application.routes.draw do

  post "/wechat_platform/authorization", to: 'wechat_platform#handle_system_event'
  get "/wechat_platform/component_verify_token", to: 'wechat_platform#get_component_verify_token'
  get "/wechat_platform/authorization/pre", to: 'wechat_platform#first_step'
  get "/wechat_platform", to: 'wechat_platform#finish'
  post "/wechat_platform/component_verify_ticket", to: 'wechat_platform#set_ticket'

  get "/user/:id/info", to: 'wechat_platform#show_user_info'
  get "/user/:id/token", to: 'wechat_platform#refresh_user_access_token'
  get "/user/:id/text", to: 'wechat_platform#post_text_to_wechat'

  post "/wechat_platform/:app_id/messages", to: 'wechat_platform#handle_wechat_message'
end
