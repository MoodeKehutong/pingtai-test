class CreateUsers < ActiveRecord::Migration
  def change
    create_table :users do |t|
      t.string :appid
      t.string :refresh_token
      t.string :access_token

      t.timestamps
    end
  end
end
