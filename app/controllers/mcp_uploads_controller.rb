# frozen_string_literal: true

# Receives the file bytes for an upload URL issued by create_attachment_upload.
# The signed ticket in the query string is this endpoint's only credential: it
# never resolves a cookie, API key, or bearer token. Everything the ticket
# vouched for at issue time is checked again here, because the upload can come
# later and from another machine. See "Attachment uploads" in ARCHITECTURE.md.
class McpUploadsController < ApplicationController
  # The ticket, not a session, authenticates the request, so there is no
  # CSRF token to check and no login redirect to apply.
  skip_before_action :verify_authenticity_token
  skip_before_action :check_if_login_required, raise: false

  before_action :require_uploads_open
  before_action :verify_origin
  before_action :authenticate_ticket

  def create
    # Same contract as core's /uploads.json: a raw body that Rails does not try
    # to parse as parameters.
    unless request.media_type == 'application/octet-stream'
      return render_error('Send the file as the raw request body with Content-Type: application/octet-stream', 415)
    end
    if request.content_length.to_i > RedmineMcp::Uploads.max_bytes
      return render_error("The file is larger than the #{Setting.attachment_max_size} KB attachment limit", 413)
    end

    attachment = RedmineMcp::Uploads.store(
      user: @user, io: request_body, filename: @ticket.filename, content_type: @ticket.content_type
    )
    return render_error(attachment.errors.full_messages.join('; '), 422) unless attachment.persisted?

    render json: RedmineMcp::Uploads.describe(attachment).merge(next_step: RedmineMcp::Uploads::NEXT_STEP),
           status: :created
  end

  private

  def require_uploads_open
    return if RedmineMcp::Settings.enabled? && !RedmineMcp::Settings.read_only?

    render_error('Uploads are not available', 403)
  end

  def verify_origin
    return if RedmineMcp::Settings.origin_allowed?(request.headers['Origin'], request.base_url)

    render_error('Origin not allowed', 403)
  end

  def authenticate_ticket
    @ticket = RedmineMcp::UploadTicket.verify(params[RedmineMcp::UploadTicket::PARAM])
    @user = @ticket && User.active.find_by(id: @ticket.user_id)
    return render_error('The upload URL is invalid or has expired', 401) if @user.nil?

    # Re-applies the OAuth scopes the issuing token held, so the upload cannot
    # exceed what that token could do through /mcp.
    @user.oauth_scope = @ticket.oauth_scopes
    return render_error(RedmineMcp::Uploads::NOT_PERMITTED, 403) unless RedmineMcp::Uploads.allowed?(@user)

    User.current = @user
  end

  def request_body
    request.body.respond_to?(:size) ? request.body : StringIO.new(request.raw_post)
  end

  def render_error(message, status)
    render json: { error: message }, status: status
  end
end
