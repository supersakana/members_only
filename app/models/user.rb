class User < ApplicationRecord
  has_many :posts

  # validates :username, presence: true, length: { in: 3..20 }

  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable, :trackable and :omniauthable
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :validatable
end
