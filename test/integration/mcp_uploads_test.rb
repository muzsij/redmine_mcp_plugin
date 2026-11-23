# frozen_string_literal: true

require File.expand_path('../test_helper', __dir__)

# Covers POST /mcp/uploads end to end: a ticket from create_attachment_upload is
# the endpoint's only credential, every gate it vouched for is re-checked at
# upload time, Redmine's attachment validations apply, and the uploaded file
# can then be attached through /mcp.
class RedmineMcpUploadsTest < Redmine::IntegrationTest
  fixtures :projects, :users, :email_addresses, :roles, :members, :member_roles,
           :issues, :issue_statuses, :trackers, :enumerations, :enabled_modules,
           :journals, :attachments, :workflows, :projects_trackers

  def setup
    super
    Setting.rest_api_enabled = '1'
    enable('read_only' => '0')
    set_tmp_attachments_directory
  end

  def teardown
    Setting.clear_cache
    super
  end

  def test_upload_url_flow_attaches_a_file_through_mcp
    created = mcp_call('create_attachment_upload', 'filename' => 'report.txt', 'content_type' => 'text/plain')
    upload_url = URI.parse(created['upload_url'])
    assert_equal 'http://www.example.com/mcp/uploads', "#{upload_url.scheme}://#{upload_url.host}#{upload_url.path}"

    post "#{upload_url.path}?#{upload_url.query}", headers: octet_stream('Quarterly numbers')
    assert_response :created
    token = response.parsed_body['token']
    assert_equal 'report.txt', response.parsed_body['filename']

    noted = mcp_call('add_issue_note', 'id' => 1, 'notes' => 'Report attached', 'uploads' => [{ 'token' => token }])
    attachment = Attachment.find(noted['attachments'].first['id'])
    assert_equal Issue.find(1), attachment.container
    assert_equal User.find(2), attachment.author
    assert_equal 'text/plain', attachment.content_type
    assert_equal 'Quarterly numbers', File.binread(attachment.diskfile)
  end

  def test_invalid_or_expired_tickets_are_rejected
    post_upload('garbage')
    assert_response :unauthorized

    value = ticket
    travel(RedmineMcp::UploadTicket::LIFETIME + 1.minute) { post_upload(value) }
    assert_response :unauthorized
  end

  def test_ticket_for_a_locked_user_is_rejected
    value = ticket
    User.find(2).lock!

    post_upload(value)
    assert_response :unauthorized
  end

  def test_uploads_close_with_read_only_mode_or_a_disabled_endpoint
    value = ticket

    enable('read_only' => '1')
    post_upload(value)
    assert_response :forbidden

    enable('enabled' => '0', 'read_only' => '0')
    post_upload(value)
    assert_response :forbidden
  end

  def test_foreign_origin_is_rejected
    post_upload(ticket, { 'Origin' => 'https://evil.example' })
    assert_response :forbidden
  end

  def test_only_raw_octet_stream_bodies_are_accepted
    post upload_path(ticket), headers: { 'RAW_POST_DATA' => 'x', 'CONTENT_TYPE' => 'text/plain' }
    assert_response :unsupported_media_type
  end

  def test_oversize_bodies_are_rejected_before_storing
    with_settings(attachment_max_size: 1) do
      assert_no_difference('Attachment.count') { post_upload(ticket, body: 'x' * 2.kilobytes) }
    end
    assert_response 413
  end

  def test_redmine_extension_rules_apply
    with_settings(attachment_extensions_denied: 'exe') do
      post_upload(ticket(filename: 'tool.exe'))
    end
    assert_response 422
    assert_match(/not allowed/i, response.parsed_body['error'])
  end

  # The ticket carries the issuing token's scopes, so an upload cannot exceed
  # what that token could do through /mcp.
  def test_recorded_oauth_scopes_are_reapplied
    post_upload(ticket(scopes: %i[view_issues]))
    assert_response :forbidden

    post_upload(ticket(scopes: %i[view_issues add_issue_notes]))
    assert_response :created
  end

  def test_the_ticket_parameter_is_filtered_from_logs
    env = Rack::MockRequest.env_for("/mcp/uploads?#{RedmineMcp::UploadTicket::PARAM}=secret-ticket")
    request = ActionDispatch::Request.new(Rails.application.env_config.merge(env))

    assert_not_includes request.filtered_path, 'secret-ticket'
  end

  private

  def enable(overrides)
    Setting.plugin_redmine_mcp = RedmineMcp::Settings::DEFAULTS.merge('enabled' => '1').merge(overrides)
    Setting.clear_cache
  end

  def ticket(user: User.find(2), filename: 'report.txt', scopes: nil)
    RedmineMcp::UploadTicket.generate(user: user, filename: filename, content_type: 'text/plain', oauth_scopes: scopes)
  end

  def upload_path(value)
    "/mcp/uploads?#{RedmineMcp::UploadTicket::PARAM}=#{CGI.escape(value)}"
  end

  def octet_stream(body)
    { 'RAW_POST_DATA' => body, 'CONTENT_TYPE' => 'application/octet-stream',
      'CONTENT_LENGTH' => body.bytesize.to_s }
  end

  def post_upload(value, headers = {}, body: 'File content')
    post upload_path(value), headers: octet_stream(body).merge(headers)
  end

  def mcp_call(name, arguments)
    post '/mcp',
         params: { jsonrpc: '2.0', id: 1, method: 'tools/call',
                   params: { name: name, arguments: arguments } }.to_json,
         headers: { 'CONTENT_TYPE' => 'application/json', 'X-Redmine-API-Key' => User.find(2).api_key }
    assert_response :success
    result = response.parsed_body['result']
    assert_not result['isError'], result.inspect
    result['structuredContent']
  end
end
