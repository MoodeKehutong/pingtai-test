Rails.application.routes.draw do

  post "/wechat_platform/authorization", to: 'wechat_platform#handle_system_event'
end
