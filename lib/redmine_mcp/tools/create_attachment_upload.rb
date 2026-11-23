# frozen_string_literal: true

module RedmineMcp
  module Tools
    class CreateAttachmentUpload < UploadBase
      tool_name 'create_attachment_upload'
      title 'Create attachment upload URL'
      description 'Get a short-lived URL for uploading a file from your own environment, such as a ' \
                  'local file or one in a code sandbox, without passing its contents through the ' \
                  'conversation. POST the raw bytes to upload_url with Content-Type: ' \
                  'application/octet-stream, for example: curl --fail --data-binary @FILE -H ' \
                  '"Content-Type: application/octet-stream" "UPLOAD_URL". The JSON response carries a ' \
                  'token; pass it in the uploads argument of create_issue, update_issue, or ' \
                  'add_issue_note. The URL expires after 15 minutes. If your environment cannot reach ' \
                  'this Redmine over HTTP, use upload_attachment_content for small files.'
      write true
      input_schema(
        'type' => 'object',
        'properties' => {
          'filename' => { 'type' => 'string', 'description' => 'Name the attachment will have.' },
          'content_type' => { 'type' => 'string', 'description' => 'MIME type, e.g. application/pdf.' }
        },
        'required' => %w[filename],
        'additionalProperties' => false
      )

      private

      def perform(arguments)
        authorize_upload!
        filename = arguments['filename'].to_s.strip
        raise ToolError, 'filename must not be empty' if filename.empty?

        ticket = UploadTicket.generate(user: user, filename: filename,
                                       content_type: arguments['content_type'].to_s.strip,
                                       oauth_scopes: oauth_scopes)
        {
          upload_url: "#{public_base_url}/mcp/uploads?#{UploadTicket::PARAM}=#{CGI.escape(ticket)}",
          method: 'POST',
          headers: { 'Content-Type' => 'application/octet-stream' },
          expires_at: iso(UploadTicket::LIFETIME.from_now),
          max_bytes: Uploads.max_bytes,
          next_step: "POST the file's raw bytes to upload_url; the JSON response carries a token. " \
                     "#{Uploads::NEXT_STEP}"
        }
      end
    end
  end
end
