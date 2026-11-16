# frozen_string_literal: true

module RedmineMcp
  # RFC 7591 Dynamic Client Registration, served by doorkeeper-openid_connect.
  # Only POST /oauth/registration is used; no ID token is ever minted.
  module DynamicClientRegistration
    LOOPBACK_HOSTS = %w[localhost 127.0.0.1 ::1].freeze
    # The methods advertised in authorization-server metadata. A confidential
    # registration is no weaker than a public one: the secret goes only to the
    # registrant, and the token endpoint then demands it on top of any PKCE.
    # Clients such as Claude register only as client_secret_post.
    ACCEPTED_AUTH_METHODS = %w[none client_secret_basic client_secret_post].freeze
    # RFC 7591 section 2 default when the client omits the method.
    DEFAULT_AUTH_METHOD = 'client_secret_basic'

    class << self
      def available?
        return @available unless @available.nil?

        @available = load!
      end

      # Load during route drawing because the gem binds controllers before
      # Redmine sets base_controller when it is required at boot.
      def load!
        require 'doorkeeper/openid_connect'
        Doorkeeper::OpenidConnect::Rails::Routes.install!
        require File.join(
          Gem.loaded_specs['doorkeeper-openid_connect'].gem_dir,
          'app/controllers/doorkeeper/openid_connect/dynamic_client_registration_controller'
        )
        true
      rescue LoadError
        false
      end

      def configure!
        Doorkeeper::OpenidConnect.configure do
          # No issuer/signing_key (no ID tokens) and no scope config: Redmine core
          # already registers permission names as Doorkeeper optional_scopes, and
          # the gem validates registration scopes against that.
          dynamic_client_registration true

          authorize_dynamic_client_registration do
            RedmineMcp::DynamicClientRegistration.permitted?(params)
          end
        end
        attach_openid_request!
      end

      # The gem adds AccessGrant#openid_request from the grant mixin's included
      # hook, but production eager-loads the grant model before this lazy require,
      # so the hook never fires and /oauth/token fails on the missing association.
      # Must run after configure, which supplies the association's class name.
      def attach_openid_request!
        grant = Doorkeeper.config.access_grant_model
        return if grant.reflect_on_association(:openid_request)

        grant.prepend(Doorkeeper::OpenidConnect::AccessGrant)
      end

      def permitted?(params)
        reason = refusal_reason(params)
        return true if reason.nil?

        # The client sees only a generic 401, so the log is where an operator
        # learns why. Registration metadata carries no credentials.
        Rails.logger.warn(
          "[redmine_mcp] dynamic client registration refused (#{reason}): " \
          "token_endpoint_auth_method=#{params[:token_endpoint_auth_method].inspect} " \
          "redirect_uris=#{Array(params[:redirect_uris]).map(&:to_s).inspect} " \
          "client_name=#{params[:client_name].to_s.truncate(100).inspect}"
        )
        false
      end

      def refusal_reason(params)
        return 'registration disabled' unless gate_open?
        return 'unsupported token endpoint auth method' unless accepted_auth_method?(params)
        return 'redirect URI not HTTPS or loopback' unless redirect_uris_acceptable?(params)

        nil
      end

      def gate_open?
        Settings.enabled? && Settings.oauth2_auth? && Settings.dcr_enabled?
      end

      def accepted_auth_method?(params)
        method = params[:token_endpoint_auth_method].presence&.to_s || DEFAULT_AUTH_METHOD
        ACCEPTED_AUTH_METHODS.include?(method)
      end

      # Every redirect URI must be loopback or HTTPS, and at least one is required.
      def redirect_uris_acceptable?(params)
        uris = Array(params[:redirect_uris])
        uris.any? && uris.all? { |uri| acceptable_redirect_uri?(uri) }
      end

      def acceptable_redirect_uri?(raw)
        uri = URI.parse(raw.to_s)
        uri.scheme == 'https' || loopback?(uri)
      rescue URI::InvalidURIError
        false
      end

      def loopback?(uri)
        LOOPBACK_HOSTS.include?(uri.host.to_s.downcase.delete('[]'))
      end
    end
  end
end
