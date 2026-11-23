# frozen_string_literal: true

module RedmineMcp
  module Tools
    class UploadAttachmentContent < UploadBase
      # The bytes travel through the model's context as base64, which costs
      # roughly a token per three characters, so this stays a small-file fallback.
      MAX_BYTES = 64.kilobytes

      tool_name 'upload_attachment_content'
      title 'Upload small attachment content'
      description 'Store a small file (at most 64 KiB) given as base64 as a pending upload. Use ' \
                  'it only when create_attachment_upload cannot be used, because the content passes ' \
                  'through the conversation. Returns a token to pass in the uploads argument of ' \
                  'create_issue, update_issue, or add_issue_note.'
      write true
      input_schema(
        'type' => 'object',
        'properties' => {
          'filename' => { 'type' => 'string', 'description' => 'Name the attachment will have.' },
          'content_base64' => { 'type' => 'string', 'maxLength' => 90_000,
                                'description' => 'The file content, base64-encoded.' },
          'content_type' => { 'type' => 'string', 'description' => 'MIME type, e.g. text/markdown.' }
        },
        'required' => %w[filename content_base64],
        'additionalProperties' => false
      )

      private

      def perform(arguments)
        authorize_upload!
        filename = arguments['filename'].to_s.strip
        raise ToolError, 'filename must not be empty' if filename.empty?

        bytes = decode(arguments['content_base64'])
        if bytes.bytesize > MAX_BYTES
          raise ToolError, 'content_base64 is limited to 64 KiB of decoded data; use create_attachment_upload'
        end

        Uploads.store!(user: user, io: StringIO.new(bytes), filename: filename,
                       content_type: arguments['content_type'].to_s.strip)
      end

      def decode(value)
        value.to_s.gsub(/\s+/, '').unpack1('m0')
      rescue ArgumentError
        raise ToolError, 'content_base64 is not valid base64'
      end
    end
  end
end
