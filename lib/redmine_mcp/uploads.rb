# frozen_string_literal: true

module RedmineMcp
  # Creates unattached attachments for the upload tools and attaches them for the
  # issue write tools. Both halves reuse Redmine's own upload model (an
  # unattached Attachment named by its token), so core's size and extension
  # validations apply whichever way the bytes arrived.
  module Uploads
    # Core grants attachments#upload through several permissions (add_issues,
    # edit_issues, add_issue_notes, ...). Checking the action instead of picking
    # one of them matches the gate on core's own /uploads endpoint, and
    # User#allowed_to? narrows it by an OAuth token's scopes.
    UPLOAD_ACTION = { controller: 'attachments', action: 'upload' }.freeze

    MAX_PER_CALL = 10

    # One message for every unusable token, so a caller cannot tell another
    # user's pending upload from a token that never existed.
    INVALID_TOKEN = 'Upload token %s is not a pending upload of yours'

    NOT_PERMITTED = 'You do not have permission to upload files'

    NEXT_STEP = 'Attach it by passing the token in the uploads argument of create_issue, ' \
                'update_issue, or add_issue_note. Unattached uploads are deleted after a day.'

    SCHEMA = {
      'type' => 'array',
      'maxItems' => MAX_PER_CALL,
      'description' => 'Files to attach, each named by the token that create_attachment_upload ' \
                       '(after the file was sent to its upload_url), upload_attachment_from_url, or ' \
                       'upload_attachment_content returned.',
      'items' => {
        'type' => 'object',
        'properties' => {
          'token' => { 'type' => 'string', 'description' => 'Upload token.' },
          'filename' => { 'type' => 'string', 'description' => 'Overrides the uploaded file name.' },
          'description' => { 'type' => 'string', 'description' => 'Attachment description.' },
          'content_type' => { 'type' => 'string', 'description' => 'Overrides the MIME type.' }
        },
        'required' => %w[token],
        'additionalProperties' => false
      }
    }.freeze

    module_function

    def allowed?(user)
      user.allowed_to?(UPLOAD_ACTION, nil, global: true)
    end

    # The role-only half of allowed?, for discovery: OAuth narrowing is
    # cleared and then restored exactly, as Tools::Base.role_allows? does.
    def role_allows?(user, oauth_scopes:)
      user.oauth_scope = nil
      allowed?(user)
    ensure
      user.oauth_scope = oauth_scopes
    end

    def max_bytes
      Setting.attachment_max_size.to_i.kilobytes
    end

    # Returns the attachment, saved or carrying its validation errors. +io+ must
    # respond to #size and #read and be positioned at its start.
    def store(user:, io:, filename:, content_type: nil)
      attachment = Attachment.new(file: io)
      attachment.author = user
      attachment.filename = filename.presence || Redmine::Utils.random_hex(16)
      attachment.content_type = content_type.presence
      attachment.save
      attachment
    end

    def store!(user:, io:, filename:, content_type: nil)
      attachment = store(user: user, io: io, filename: filename, content_type: content_type)
      unless attachment.persisted?
        raise ToolError, "Could not store the upload: #{attachment.errors.full_messages.join('; ')}"
      end

      describe(attachment).merge(next_step: NEXT_STEP)
    end

    def describe(attachment)
      { token: attachment.token, filename: attachment.filename,
        content_type: attachment.content_type, filesize: attachment.filesize }
    end

    # Queues +entries+ on +issue+ through core's Issue#save_attachments; the
    # issue's own save then attaches them. Every entry is checked before
    # anything is queued, so one bad token rejects the whole call rather than
    # attaching part of the set. Returns the queued attachments.
    def queue!(issue, user, entries)
      entries = Array(entries).uniq { |entry| entry['token'].to_s }
      return [] if entries.empty?
      raise ToolError, "At most #{MAX_PER_CALL} uploads can be attached per call" if entries.size > MAX_PER_CALL

      prepared = entries.map do |entry|
        token = entry['token'].to_s
        attachment = Attachment.find_by_token(token)
        # Core's find_by_token does not check the uploader, and a token is only
        # the id plus the content's SHA-256, which anyone holding the same file
        # can compute. Only the caller's own pending uploads are attachable.
        raise ToolError, format(INVALID_TOKEN, token.inspect) unless attachment&.author_id == user.id

        entry.slice('token', 'filename', 'description', 'content_type')
      end

      result = issue.save_attachments(prepared, user)
      # Core keeps an upload that fails validation after a rename out of the
      # save without failing it; report that instead of dropping the file.
      if result[:unsaved].any?
        messages = result[:unsaved].flat_map { |a| a.errors.full_messages }.uniq
        raise ToolError, "Could not attach #{result[:unsaved].map(&:filename).join(', ')}: #{messages.join('; ')}"
      end

      result[:files]
    end

    def summarize(attachments)
      attachments.map do |attachment|
        { id: attachment.id, filename: attachment.filename,
          content_type: attachment.content_type, filesize: attachment.filesize }
      end
    end
  end
end
