# frozen_string_literal: true

module RedmineMcp
  # The signed ticket in an upload URL. It is the upload endpoint's only
  # credential, so it records everything that endpoint must re-check: who the
  # upload is for and which OAuth scopes that caller's token held. It is not
  # single-use; within its lifetime it can only create further unattached
  # uploads owned by the same user.
  module UploadTicket
    PURPOSE = 'redmine_mcp_upload'
    LIFETIME = 15.minutes
    PARAM = 'upload_token'

    Ticket = Struct.new(:user_id, :filename, :content_type, :oauth_scopes, keyword_init: true)

    module_function

    def generate(user:, filename:, content_type:, oauth_scopes:)
      payload = { 'u' => user.id, 'f' => filename.to_s, 'c' => content_type.to_s,
                  's' => oauth_scopes&.map(&:to_s) }
      verifier.generate(payload, purpose: PURPOSE, expires_in: LIFETIME)
    end

    # nil for a forged, expired, or differently purposed ticket.
    def verify(value)
      data = verifier.verified(value.to_s, purpose: PURPOSE)
      return nil unless data.is_a?(Hash) && data['u'].is_a?(Integer)

      Ticket.new(user_id: data['u'], filename: data['f'].to_s, content_type: data['c'].to_s,
                 oauth_scopes: data['s']&.map(&:to_sym))
    rescue ArgumentError, ActiveSupport::MessageVerifier::InvalidSignature
      nil
    end

    def verifier
      Rails.application.message_verifier(PURPOSE)
    end
  end
end
