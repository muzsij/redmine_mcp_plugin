# frozen_string_literal: true

require File.expand_path('../test_helper', __dir__)

# Covers the upload tools and the uploads argument of the issue write tools
# through a mounted MCP::Server: tokens are owner-bound and all-or-nothing,
# attachments land on the issue and in its journal, Redmine's attachment rules
# still apply, and the tools follow read-only mode, OAuth scopes, and the
# server-side download switch.
class RedmineMcpAttachmentUploadToolsTest < ActiveSupport::TestCase
  fixtures :projects, :users, :email_addresses, :roles, :members, :member_roles,
           :issues, :issue_statuses, :trackers, :enumerations, :enabled_modules,
           :journals, :journal_details, :attachments, :workflows, :projects_trackers,
           :issue_categories, :versions, :custom_fields, :custom_fields_projects,
           :custom_fields_trackers, :custom_values

  def setup
    Setting.plugin_redmine_mcp = RedmineMcp::Settings::DEFAULTS.merge('read_only' => '0')
    Setting.clear_cache
    set_tmp_attachments_directory
    @jsmith = User.find(2)
  end

  def teardown
    Setting.clear_cache
    User.current = nil
  end

  def test_upload_content_creates_a_pending_upload_owned_by_the_caller
    result = call(@jsmith, 'upload_attachment_content',
                  'filename' => 'notes.txt', 'content_base64' => encode('hello'), 'content_type' => 'text/plain')

    assert_not result[:isError], result.inspect
    attachment = Attachment.find_by_token(result[:structuredContent][:token])
    assert_equal @jsmith, attachment.author
    assert_nil attachment.container
    assert_equal 'notes.txt', attachment.filename
    assert_equal 'text/plain', attachment.content_type
    assert_equal 'hello', File.binread(attachment.diskfile)
  end

  def test_add_issue_note_attaches_uploads_without_notes_and_journals_them
    token = upload(@jsmith)
    result = call(@jsmith, 'add_issue_note', 'id' => 1,
                                             'uploads' => [{ 'token' => token, 'description' => 'Signed copy' }])

    assert_not result[:isError], result.inspect
    attached = result[:structuredContent][:attachments]
    assert_equal ['notes.txt'], attached.pluck(:filename)
    attachment = Attachment.find(attached.first[:id])
    assert_equal Issue.find(1), attachment.container
    assert_equal 'Signed copy', attachment.description
    journal = Journal.find(result[:structuredContent][:journal_id])
    assert(journal.details.any? { |d| d.property == 'attachment' && d.prop_key == attachment.id.to_s })
  end

  def test_add_issue_note_still_needs_notes_or_uploads
    result = call(@jsmith, 'add_issue_note', 'id' => 1)

    assert result[:isError]
    assert_equal 'notes must not be empty', text(result)
  end

  def test_update_issue_attaches_uploads_and_journals_them
    token = upload(@jsmith)
    result = call(@jsmith, 'update_issue', 'id' => 1, 'uploads' => [{ 'token' => token, 'filename' => 'renamed.txt' }])

    assert_not result[:isError], result.inspect
    assert_equal ['renamed.txt'], Issue.find(1).attachments.map(&:filename) & ['renamed.txt']
    journal = Issue.find(1).journals.order(:id).last
    assert(journal.details.any? { |d| d.property == 'attachment' && d.value == 'renamed.txt' })
  end

  def test_create_issue_attaches_uploads
    token = upload(@jsmith)
    result = call(@jsmith, 'create_issue', 'project' => 'ecookbook', 'subject' => 'With a file',
                                           'uploads' => [{ 'token' => token }])

    assert_not result[:isError], result.inspect
    issue = Issue.find(result[:structuredContent][:id])
    assert_equal ['notes.txt'], issue.attachments.map(&:filename)
    assert_equal ['notes.txt'], result[:structuredContent][:attachments].pluck(:filename)
  end

  # Core resolves a token by id and content digest alone, so knowing the file
  # would be enough to claim someone else's upload. The plugin refuses that with
  # the same message as a token that does not exist or is already attached.
  def test_tokens_of_other_users_unknown_or_attached_are_refused_alike
    foreign = upload(User.find(3))
    attached = Attachment.find(1).token

    [foreign, '999999.abcdef', attached].each do |token|
      result = call(@jsmith, 'add_issue_note', 'id' => 1, 'uploads' => [{ 'token' => token }])

      assert result[:isError], token
      assert_equal format(RedmineMcp::Uploads::INVALID_TOKEN, token.inspect), text(result)
    end
    assert_nil Attachment.find_by_token(foreign).container
  end

  def test_one_bad_token_attaches_nothing
    good = upload(@jsmith)
    before = Issue.find(1).attachments.count
    result = call(@jsmith, 'update_issue', 'id' => 1, 'subject' => 'Changed',
                                           'uploads' => [{ 'token' => good }, { 'token' => '1.bad' }])

    assert result[:isError]
    assert_equal before, Issue.find(1).attachments.count
    assert_nil Attachment.find_by_token(good).container
    assert_not_equal 'Changed', Issue.find(1).subject
  end

  def test_redmine_extension_rules_apply_to_uploads_and_renames
    with_settings(attachment_extensions_denied: 'exe') do
      result = call(@jsmith, 'upload_attachment_content', 'filename' => 'tool.exe', 'content_base64' => encode('x'))
      assert result[:isError]
      assert_match(/Could not store the upload/, text(result))

      token = upload(@jsmith)
      result = call(@jsmith, 'add_issue_note', 'id' => 1,
                                               'uploads' => [{ 'token' => token, 'filename' => 'tool.exe' }])
      assert result[:isError]
      assert_match(/Could not attach tool\.exe/, text(result))
    end
  end

  def test_upload_content_rejects_bad_base64_and_oversize_content
    result = call(@jsmith, 'upload_attachment_content', 'filename' => 'a.txt', 'content_base64' => 'not base64!')
    assert_equal 'content_base64 is not valid base64', text(result)

    big = encode('x' * (RedmineMcp::Tools::UploadAttachmentContent::MAX_BYTES + 1))
    result = call(@jsmith, 'upload_attachment_content', 'filename' => 'a.txt', 'content_base64' => big)
    assert result[:isError]
  end

  def test_create_attachment_upload_returns_a_signed_url_for_the_caller
    result = call(@jsmith, 'create_attachment_upload', 'filename' => 'report.pdf', 'content_type' => 'application/pdf')

    assert_not result[:isError], result.inspect
    url = URI.parse(result[:structuredContent][:upload_url])
    assert_equal 'https://redmine.test/mcp/uploads', "#{url.scheme}://#{url.host}#{url.path}"
    ticket = RedmineMcp::UploadTicket.verify(CGI.parse(url.query)['upload_token'].first)
    assert_equal [2, 'report.pdf', 'application/pdf', nil],
                 [ticket.user_id, ticket.filename, ticket.content_type, ticket.oauth_scopes]
  end

  def test_upload_tools_are_hidden_in_read_only_mode
    Setting.plugin_redmine_mcp = RedmineMcp::Settings::DEFAULTS.merge('read_only' => '1')
    Setting.clear_cache

    names = tool_names(@jsmith)
    assert_not_includes names, 'create_attachment_upload'
    assert_not_includes names, 'upload_attachment_content'
  end

  # Discovery follows the role; execution intersects it with the token, so a
  # token without any permission that grants core's upload action is refused.
  def test_oauth_token_without_an_upload_permission_is_refused
    auth = { mode: :oauth2, scopes: %i[view_issues view_project] }
    @jsmith.oauth_scope = auth[:scopes]

    assert_includes tool_names(@jsmith, auth: auth), 'upload_attachment_content'
    result = call(@jsmith, 'upload_attachment_content', { 'filename' => 'a.txt', 'content_base64' => encode('x') },
                  auth)
    assert_equal RedmineMcp::Uploads::NOT_PERMITTED, text(result)
  ensure
    @jsmith.oauth_scope = nil
  end

  def test_oauth_token_with_add_issue_notes_may_upload
    auth = { mode: :oauth2, scopes: %i[view_issues add_issue_notes] }
    @jsmith.oauth_scope = auth[:scopes]

    result = call(@jsmith, 'upload_attachment_content', { 'filename' => 'a.txt', 'content_base64' => encode('x') },
                  auth)
    assert_not result[:isError], result.inspect
  ensure
    @jsmith.oauth_scope = nil
  end

  def test_url_upload_is_hidden_and_refused_until_enabled
    assert_not_includes tool_names(@jsmith), 'upload_attachment_from_url'

    result = RedmineMcp::Tools::UploadAttachmentFromUrl.new(@jsmith, { mode: :api_key })
                                                       .run('url' => 'https://files.example.com/a.pdf')
    assert result.error?
    assert_equal RedmineMcp::Tools::Base::UNAVAILABLE, result.content.first[:text]
  end

  def test_url_upload_stores_the_downloaded_file_when_enabled
    Setting.plugin_redmine_mcp = RedmineMcp::Settings::DEFAULTS.merge('read_only' => '0', 'url_upload_enabled' => '1')
    Setting.clear_cache
    file = Tempfile.new('download', binmode: true)
    file.write('%PDF-1.7')
    file.rewind
    download = RedmineMcp::UrlFetcher::Download.new(io: file, filename: 'invoice.pdf',
                                                    content_type: 'application/pdf', size: 8)
    RedmineMcp::UrlFetcher.expects(:fetch).with('https://files.example.com/a', max_bytes: RedmineMcp::Uploads.max_bytes)
                          .returns(download)

    assert_includes tool_names(@jsmith), 'upload_attachment_from_url'
    result = call(@jsmith, 'upload_attachment_from_url', 'url' => 'https://files.example.com/a')

    assert_not result[:isError], result.inspect
    attachment = Attachment.find_by_token(result[:structuredContent][:token])
    assert_equal %w[invoice.pdf application/pdf], [attachment.filename, attachment.content_type]
    assert_equal @jsmith, attachment.author
  end

  private

  def server(user, auth:)
    RedmineMcp::McpServer.build(
      tools: RedmineMcp::Registry.all.select { |tool| tool.available_to?(user, oauth_scopes: auth[:scopes]) },
      server_context: { user: user, auth: auth, base_url: 'https://redmine.test' }
    )
  end

  # Positional auth: a braceless string-keyed arguments hash would otherwise be
  # taken as keywords.
  def call(user, name, arguments = {}, auth = { mode: :api_key })
    User.current = user
    server(user, auth: auth).handle(
      { jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: name, arguments: arguments } }
    )[:result]
  end

  def tool_names(user, auth: { mode: :api_key })
    server(user, auth: auth).handle({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} })[:result][:tools]
                            .pluck(:name)
  end

  def upload(user, filename: 'notes.txt', content: 'hello')
    result = call(user, 'upload_attachment_content', 'filename' => filename, 'content_base64' => encode(content))
    assert_not result[:isError], result.inspect
    result[:structuredContent][:token]
  end

  def encode(bytes)
    [bytes].pack('m0')
  end

  def text(result)
    result[:content].first[:text]
  end
end
