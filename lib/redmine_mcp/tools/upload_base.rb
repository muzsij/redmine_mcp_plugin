# frozen_string_literal: true

module RedmineMcp
  module Tools
    # Shared gate for the tools that create an unattached upload. They declare no
    # single permission, because core grants its upload action through several
    # (see Uploads::UPLOAD_ACTION), so discovery and execution check that action
    # here. Not registered itself; subclasses must still declare `write true`,
    # since the flag is per class.
    class UploadBase < Base
      def self.available_to?(user, oauth_scopes:)
        super && Uploads.role_allows?(user, oauth_scopes: oauth_scopes)
      end

      private

      def authorize_upload!
        raise ToolError, Uploads::NOT_PERMITTED unless Uploads.allowed?(user)
      end
    end
  end
end
