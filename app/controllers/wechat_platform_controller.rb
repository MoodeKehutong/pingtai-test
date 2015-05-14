class WechatPlatformController < ApplicationController

  def handle_system_event
    logger.info '-----------handle system event------------'
    logger.info params
    render text: 'success'
  end

end
