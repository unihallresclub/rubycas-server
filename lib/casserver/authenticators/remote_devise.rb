require 'casserver/authenticators/base'
require 'uri'
require 'net/http'
require 'net/https'
require 'timeout'

# Validates accounts against a remote Devise installation using its JSON API.
#
# For example:
#
#   authenticator:
#     class: CASServer::Authenticators::RemoteDevise
#     url: https://devise.url/users/sign_in.json
#     auth_options:
#       model: user
#       attribute: username
#     timeout: 10
#
# Definitions:
#   url -- The URL (ending in .json) of the page that login information is POSTed to.
#   model -- The lowercase name of the model being authenticated. Defaults to 'user'.
#   attribute -- The name of the attribute used as the username. Defaults to 'email'.
#   timeout -- Number of seconds to wait for response from Devise. Defaults to 10 seconds.
#
# All user account attributes are available as extra attributes. To avoid conflicts, if a :username attribute is added
# to the extra attributes, it will be renamed to :username_devise.
class CASServer::Authenticators::RemoteDevise < CASServer::Authenticators::Base
  def self.setup(options)
    raise CASServer::AuthenticatorError, "No Devise URL provided" unless options[:url]

    @url = options[:url]
    @auth_model = options[:auth_options][:model] || 'user'
    @auth_attribute = options[:auth_options][:attribute] || 'email'
    @timeout = options[:timeout] || 10
  end

  def validate(credentials)
    read_standard_credentials(credentials)

    return false if @username.blank? || @password.blank?

    auth_data = {
      "#{@auth_model}[#{@auth_attribute}]"   => @username,
      "#{@auth_model}[password]"             => @password,
    }

    url = URI.parse(@url)
    if @options[:proxy]
      http = Net::HTTP.Proxy(@options[:proxy][:host], @options[:proxy][:port], @options[:proxy][:username], @options[:proxy][:password]).new(url.host, url.port)
    else
      http = Net::HTTP.new(url.host, url.port)
    end

    if url.scheme == "https"
      http.use_ssl = true
    else
      http.use_ssl = false
    end

    begin
      timeout(@timeout) do
        res = http.start do |conn|
          req = Net::HTTP::Post.new(url.path)
          req.set_form_data(auth_data,'&')
          conn.request(req)
        end

        case res
        when Net::HTTPSuccess

          content_type = response['content-type'].split(';')[0]
          if content_type != 'application/json'
            $LOG.error("Devise didn't return application/json content-type. Instead; #{content_type}")
            raise CASServer::AuthenticatorError, "Devise didn't return application/json content-type."
          end

          begin
            json = ActiveSupport::JSON.decode(res.body)
          rescue Exception => e
            $LOG.error("Unable to decode Devise's JSON response. Exception: #{e}")
            raise CASServer::AuthenticatorError, "Unable to decode Devise's JSON response."
          end

          if json[:error]
            $LOG.error("Unable to login because: #{json[:error]}")
            raise CASServer::AuthenticatorError, json[:error]
          end

          @extra_attributes = json[@auth_model.to_sym]

          if @extra_attributes[:username]
            @extra_attributes[:username_devise] = @extra_attributes[:username]
            @extra_attributes.delete(:username)
          end

          return true
        else
          $LOG.error("Unexpected response from Devise while validating credentials: #{res.inspect} ==> #{res.body}.")
          raise CASServer::AuthenticatorError, "Unexpected response received from Devise while validating credentials."
        end
      end
    rescue Timeout::Error
      $LOG.error("Devise did not respond to the credential validation request. We waited for #{wait_seconds.inspect} seconds before giving up.")
      raise CASServer::AuthenticatorError, "Timeout while waiting for Devise to validate credentials."
    end

  end
end
