# frozen_string_literal: true

module RedmineMcp
  module Tools
    class UploadAttachmentFromUrl < UploadBase
      tool_name 'upload_attachment_from_url'
      title 'Upload attachment from URL'
      description 'Have the Redmine server download a file from an https URL and keep it as a ' \
                  'pending upload. Use it for a link another tool returned, such as a pre-signed ' \
                  'download link; the link must work without your credentials. Returns a token to ' \
                  'pass in the uploads argument of create_issue, update_issue, or add_issue_note.'
      write true
      input_schema(
        'type' => 'object',
        'properties' => {
          'url' => { 'type' => 'string', 'description' => 'https URL of the file.' },
          'filename' => { 'type' => 'string',
                          'description' => 'Name the attachment will have. Defaults to the name the ' \
                                           'server reports, or the last path segment of the URL.' },
          'content_type' => { 'type' => 'string',
                              'description' => 'MIME type. Defaults to the type the server reports.' }
        },
        'required' => %w[url],
        'additionalProperties' => false
      )

      # Hidden unless an administrator enabled server-side downloads.
      def self.available_to?(user, oauth_scopes:)
        Settings.url_upload_enabled? && super
      end

      private

      def perform(arguments)
        raise ToolError, UNAVAILABLE unless Settings.url_upload_enabled?

        authorize_upload!
        download = UrlFetcher.fetch(arguments['url'], max_bytes: Uploads.max_bytes)
        begin
          Uploads.store!(user: user, io: download.io,
                         filename: arguments['filename'].presence || download.filename,
                         content_type: arguments['content_type'].presence || download.content_type)
        ensure
          download.io.close!
        end
      end
    end
  end
end
