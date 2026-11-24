# frozen_string_literal: true

require File.expand_path('../test_helper', __dir__)

class McpControllerTest < Redmine::ControllerTest
  tests McpController
  fixtures :projects, :users, :email_addresses, :roles, :members, :member_roles,
           :issues, :issue_statuses, :trackers, :enumerations, :enabled_modules, :time_entries, :issue_categories, :versions, :issue_relations, :workflows, :projects_trackers,
           :journals, :journal_details, :watchers

  # The bootstrap challenge advertises OAUTH_BOOTSTRAP_SCOPES: the three core read
  # scopes, the two read satellites (watchers, time entries) and
  # view_private_notes. No write scope while read-only mode is on.
  OAUTH_CHALLENGE =
    'Bearer realm="Redmine", resource_metadata="http://test.host/.well-known/oauth-protected-resource/mcp", ' \
    'scope="view_issues view_project view_wiki_pages view_issue_watchers view_time_entries view_private_notes"'

  def setup
    Setting.rest_api_enabled = '1'
    enable_mcp('enabled' => '1')
    User.current = nil
  end

  def teardown
    Setting.clear_cache
    User.current = nil
  end

  def enable_mcp(overrides = {})
    Setting.plugin_redmine_mcp =
      RedmineMcp::Settings::DEFAULTS.merge('enabled' => '1').merge(overrides)
    Setting.clear_cache
  end

  def rpc(method, params = nil, id: 1)
    body = { jsonrpc: '2.0', id: id, method: method }
    body[:params] = params if params
    body.to_json
  end

  # ActionController::TestCase#post takes no headers: keyword (that is the
  # integration-test API); request headers go on @request instead.
  def post_mcp(payload, headers = {})
    @request.headers.merge!(
      'Authorization' => nil,
      'X-Redmine-API-Key' => nil,
      'Origin' => nil
    )
    @request.headers.merge!(headers)
    post :handle, body: payload
  end

  def json_body
    JSON.parse(response.body)
  end

  def api_key_headers(user)
    { 'X-Redmine-API-Key' => user.api_key }
  end

  def oauth_headers(user, scopes:)
    application = Doorkeeper::Application.create!(
      name: 'MCP controller test', redirect_uri: 'https://client.example/callback', scopes: scopes
    )
    token = Doorkeeper::AccessToken.create!(
      application_id: application.id, resource_owner_id: user.id, scopes: scopes, expires_in: 7200
    )
    { 'Authorization' => "Bearer #{token.plaintext_token}" }
  end

  def test_endpoint_is_off_until_enabled
    enable_mcp('enabled' => '0')
    post_mcp rpc('tools/list'), api_key_headers(User.find(2))
    assert_response :forbidden
  end

  def test_unauthenticated_request_is_rejected
    post_mcp rpc('tools/list')

    assert_response :unauthorized
    assert_equal OAUTH_CHALLENGE, response.headers['WWW-Authenticate']
  end

  # Claude does not accumulate step-up grants, so with writes enabled the initial
  # challenge must already request the write tools' scopes.
  def test_unauthenticated_challenge_includes_write_scopes_when_writes_are_enabled
    enable_mcp('read_only' => '0')

    post_mcp rpc('tools/list')

    assert_response :unauthorized
    scopes = response.headers['WWW-Authenticate'][/scope="([^"]*)"/, 1].split
    assert_equal RedmineMcp::OauthScopes.initial, scopes
    assert_includes scopes, 'add_issues'
    assert_includes scopes, 'edit_issues'
    assert_includes scopes, 'log_time'
  end

  def test_insufficient_scope_challenge_is_logged
    enable_mcp('read_only' => '0')
    oauth = oauth_headers(User.find(2), scopes: 'view_issues')
    Rails.logger.expects(:warn).with(
      regexp_matches(/insufficient_scope for tool "create_issue".*required=\["add_issues"\].*challenged="add_issues add_issue_notes"/)
    )

    post_mcp rpc('tools/call', { 'name' => 'create_issue',
                                 'arguments' => { 'project' => 'ecookbook', 'subject' => 'x' } }), oauth

    assert_response :forbidden
  end

  def test_invalid_oauth_token_challenge_includes_minimal_bootstrap_scopes
    post_mcp rpc('tools/list'), 'Authorization' => 'Bearer invalid-token'

    assert_response :unauthorized
    assert_equal OAUTH_CHALLENGE, response.headers['WWW-Authenticate']
  end

  def test_invalid_api_key_is_rejected
    post_mcp rpc('tools/list'), 'X-Redmine-API-Key' => 'nonsense'
    assert_response :unauthorized
  end

  def test_disabled_api_key_mode_rejects_a_valid_key
    enable_mcp('auth_api_key' => '0', 'auth_oauth2' => '0', 'auth_basic' => '0', 'auth_session' => '0')
    post_mcp rpc('tools/list'), api_key_headers(User.find(2))
    assert_response :service_unavailable
  end

  def test_api_key_mode_requires_rest_api_enabled
    Setting.rest_api_enabled = '0'
    post_mcp rpc('tools/list'), api_key_headers(User.find(2))
    assert_response :unauthorized
  end

  def test_invalid_bearer_does_not_fall_back_to_a_valid_api_key
    post_mcp rpc('tools/list'), api_key_headers(User.find(2)).merge('Authorization' => 'Bearer invalid')

    assert_response :unauthorized
  end

  def test_valid_basic_credentials_authenticate_the_caller
    enable_mcp('auth_basic' => '1')
    header = ActionController::HttpAuthentication::Basic.encode_credentials('jsmith', 'jsmith')

    post_mcp rpc('tools/call', { 'name' => 'whoami', 'arguments' => {} }), 'Authorization' => header

    assert_response :success
    assert_equal 2, json_body.dig('result', 'structuredContent', 'id')
  end

  def test_basic_password_is_refused_when_two_factor_authentication_is_active
    enable_mcp('auth_basic' => '1')
    User.find(2).update_column(:twofa_scheme, 'totp')
    header = ActionController::HttpAuthentication::Basic.encode_credentials('jsmith', 'jsmith')

    post_mcp rpc('tools/list'), 'Authorization' => header

    assert_response :unauthorized
    assert_match(/two-factor/, json_body['error'])
  end

  def test_basic_password_is_refused_when_a_password_change_is_required
    enable_mcp('auth_basic' => '1')
    User.find(2).update_column(:must_change_passwd, true)
    header = ActionController::HttpAuthentication::Basic.encode_credentials('jsmith', 'jsmith')

    post_mcp rpc('tools/list'), 'Authorization' => header

    assert_response :forbidden
  end

  def test_invalid_basic_credentials_do_not_fall_back_to_a_valid_session
    enable_mcp('auth_basic' => '1', 'auth_session' => '1')
    user = User.find(2)
    @request.session[:user_id] = user.id
    @request.session[:tk] = user.generate_session_token
    header = ActionController::HttpAuthentication::Basic.encode_credentials('', 'invalid')

    post_mcp rpc('tools/list'), 'Authorization' => header, 'Origin' => 'http://test.host'

    assert_response :unauthorized
  end

  def test_session_authentication_works_when_the_rest_api_is_disabled
    enable_mcp('auth_session' => '1')
    Setting.rest_api_enabled = '0'
    user = User.find(2)
    @request.session[:user_id] = user.id
    @request.session[:tk] = user.generate_session_token

    post_mcp rpc('tools/call', { 'name' => 'whoami', 'arguments' => {} }), 'Origin' => 'http://test.host'

    assert_response :success
    assert_equal 'session', json_body.dig('result', 'structuredContent', 'authentication_mode')
    assert_equal user.id, json_body.dig('result', 'structuredContent', 'id')
  end

  def test_session_credentials_are_refused_when_the_mode_is_disabled
    user = User.find(2)
    @request.session[:user_id] = user.id
    @request.session[:tk] = user.generate_session_token

    post_mcp rpc('tools/list'), 'Origin' => 'http://test.host'

    assert_response :unauthorized
  end

  def test_foreign_origin_cannot_use_session_authentication
    enable_mcp('auth_session' => '1')
    user = User.find(2)
    @request.session[:user_id] = user.id
    @request.session[:tk] = user.generate_session_token

    post_mcp rpc('tools/list'), 'Origin' => 'https://evil.example'

    assert_response :forbidden
    assert_equal 'Origin not allowed', json_body['error']
  end

  def test_revoked_oauth_tokens_are_refused
    headers = oauth_headers(User.find(2), scopes: 'view_issues')
    Doorkeeper::AccessToken.last.revoke

    post_mcp rpc('tools/list'), headers

    assert_response :unauthorized
  end

  def test_expired_oauth_tokens_are_refused
    headers = oauth_headers(User.find(2), scopes: 'view_issues')
    Doorkeeper::AccessToken.last.update_columns(created_at: 3.hours.ago, expires_in: 3600)

    post_mcp rpc('tools/list'), headers

    assert_response :unauthorized
  end

  def test_oauth_tokens_for_locked_users_are_refused
    headers = oauth_headers(User.find(2), scopes: 'view_issues')
    User.find(2).lock!

    post_mcp rpc('tools/list'), headers

    assert_response :unauthorized
  end

  def test_private_journals_require_the_oauth_scope_even_when_the_role_permits_them
    Role.find(1).add_permission! :view_private_notes
    Journal.find(1).update_columns(private_notes: true, notes: 'Confidential journal')

    post_mcp rpc('tools/call', { 'name' => 'get_issue', 'arguments' => { 'id' => 1 } }),
             oauth_headers(User.find(2), scopes: 'view_issues')

    assert_response :success
    journals = json_body.dig('result', 'structuredContent', 'journals')
    assert_not_nil journals
    assert_not_includes journals.map { |journal| journal['id'] }, 1
    assert_not_includes response.body, 'Confidential journal'
    assert_includes journals.map { |journal| journal['id'] }, 2
  end

  def test_private_journals_are_returned_when_role_and_oauth_scope_both_permit_them
    Role.find(1).add_permission! :view_private_notes
    Journal.find(1).update_columns(private_notes: true, notes: 'Confidential journal')

    post_mcp rpc('tools/call', { 'name' => 'get_issue', 'arguments' => { 'id' => 1 } }),
             oauth_headers(User.find(2), scopes: 'view_issues view_private_notes')

    assert_response :success
    assert_includes json_body.dig('result', 'structuredContent', 'journals').map { |journal| journal['id'] }, 1
  end

  def test_private_journal_scope_cannot_overcome_a_role_denial
    Role.all.each { |role| role.remove_permission! :view_private_notes }
    Journal.find(1).update_column(:private_notes, true)

    post_mcp rpc('tools/call', { 'name' => 'get_issue', 'arguments' => { 'id' => 1 } }),
             oauth_headers(User.find(2), scopes: 'view_issues view_private_notes')

    assert_response :success
    assert_not_includes json_body.dig('result', 'structuredContent', 'journals').map { |journal| journal['id'] }, 1
  end

  def test_authors_can_read_their_own_private_journals_without_the_private_notes_scope
    Journal.find(2).update_column(:private_notes, true)

    post_mcp rpc('tools/call', { 'name' => 'get_issue', 'arguments' => { 'id' => 1 } }),
             oauth_headers(User.find(2), scopes: 'view_issues')

    assert_response :success
    assert_includes json_body.dig('result', 'structuredContent', 'journals').map { |journal| journal['id'] }, 2
  end

  def test_notes_filters_do_not_probe_private_notes_without_the_oauth_scope
    Role.find(1).add_permission! :view_private_notes
    Journal.find(1).update_columns(private_notes: true, notes: 'Confidential journal')
    headers = oauth_headers(User.find(2), scopes: 'view_issues')

    { '~' => [], '!~' => [1] }.each do |operator, expected|
      post_mcp rpc('tools/call', { 'name' => 'search_issues', 'arguments' => {
        'filters' => { 'issue_id' => { 'operator' => '=', 'values' => ['1'] },
                       'notes' => { 'operator' => operator, 'values' => ['Confidential journal'] } }
      } }), headers

      assert_response :success
      assert_equal expected, json_body.dig('result', 'structuredContent', 'issues').map { |issue| issue['id'] }
    end
  end

  def test_notes_filters_match_private_notes_with_the_oauth_scope
    Role.find(1).add_permission! :view_private_notes
    Journal.find(1).update_columns(private_notes: true, notes: 'Confidential journal')

    post_mcp rpc('tools/call', { 'name' => 'search_issues', 'arguments' => {
      'filters' => { 'notes' => { 'operator' => '~', 'values' => ['Confidential journal'] } }
    } }), oauth_headers(User.find(2), scopes: 'view_issues view_private_notes')

    assert_response :success
    assert_equal [1], json_body.dig('result', 'structuredContent', 'issues').map { |issue| issue['id'] }
  end

  def test_journal_author_filters_ignore_private_notes_without_the_oauth_scope
    Role.find(1).add_permission! :view_private_notes
    Journal.find(1).update_columns(user_id: 2, private_notes: false)
    Journal.find(2).update_columns(user_id: 1, private_notes: true)
    headers = oauth_headers(User.find(2), scopes: 'view_issues')

    %w[updated_by last_updated_by].each do |filter|
      post_mcp rpc('tools/call', { 'name' => 'search_issues', 'arguments' => {
        'filters' => { 'issue_id' => { 'operator' => '=', 'values' => ['1'] },
                       filter => { 'operator' => '=', 'values' => [User.find(1).name] } }
      } }), headers

      assert_response :success
      assert_equal [], json_body.dig('result', 'structuredContent', 'issues').map { |issue| issue['id'] }, filter
    end
  end

  def test_last_updated_by_uses_the_latest_scope_visible_journal
    Role.find(1).add_permission! :view_private_notes
    Journal.find(1).update_columns(user_id: 2, private_notes: false)
    Journal.find(2).update_columns(user_id: 1, private_notes: true)

    post_mcp rpc('tools/call', { 'name' => 'search_issues', 'arguments' => {
      'filters' => { 'issue_id' => { 'operator' => '=', 'values' => ['1'] },
                     'last_updated_by' => { 'operator' => '=', 'values' => ['me'] } }
    } }), oauth_headers(User.find(2), scopes: 'view_issues')

    assert_response :success
    assert_equal [1], json_body.dig('result', 'structuredContent', 'issues').map { |issue| issue['id'] }
  end

  def test_journal_author_filters_can_match_private_notes_with_the_oauth_scope
    Role.find(1).add_permission! :view_private_notes
    Journal.find(1).update_columns(user_id: 2, private_notes: false)
    Journal.find(2).update_columns(user_id: 1, private_notes: true)
    headers = oauth_headers(User.find(2), scopes: 'view_issues view_private_notes')

    %w[updated_by last_updated_by].each do |filter|
      { '=' => [1], '!' => [] }.each do |operator, expected|
        post_mcp rpc('tools/call', { 'name' => 'search_issues', 'arguments' => {
          'filters' => { 'issue_id' => { 'operator' => '=', 'values' => ['1'] },
                         filter => { 'operator' => operator, 'values' => [User.find(1).name] } }
        } }), headers

        assert_response :success
        assert_equal expected, json_body.dig('result', 'structuredContent', 'issues').map { |issue| issue['id'] }, filter
      end
    end
  end

  def test_notes_filters_can_match_the_callers_own_private_notes_without_the_scope
    Journal.find(2).update_columns(private_notes: true, notes: 'My private journal')

    post_mcp rpc('tools/call', { 'name' => 'search_issues', 'arguments' => {
      'filters' => { 'notes' => { 'operator' => '~', 'values' => ['My private journal'] } }
    } }), oauth_headers(User.find(2), scopes: 'view_issues')

    assert_response :success
    assert_equal [1], json_body.dig('result', 'structuredContent', 'issues').map { |issue| issue['id'] }
  end

  def test_native_watcher_filter_does_not_probe_other_watchers_without_the_oauth_scope
    Role.find(1).add_permission! :view_issue_watchers
    headers = oauth_headers(User.find(2), scopes: 'view_issues')

    { '=' => [], '!' => [2] }.each do |operator, expected|
      post_mcp rpc('tools/call', { 'name' => 'search_issues', 'arguments' => {
        'filters' => { 'issue_id' => { 'operator' => '=', 'values' => ['2'] },
                       'watcher_id' => { 'operator' => operator, 'values' => ['3'] } }
      } }), headers

      assert_response :success
      assert_equal expected, json_body.dig('result', 'structuredContent', 'issues').map { |issue| issue['id'] }
    end
  end

  def test_native_watcher_filter_matches_other_watchers_with_the_oauth_scope
    Role.find(1).add_permission! :view_issue_watchers

    post_mcp rpc('tools/call', { 'name' => 'search_issues', 'arguments' => {
      'filters' => { 'issue_id' => { 'operator' => '=', 'values' => ['2'] },
                     'watcher_id' => { 'operator' => '=', 'values' => ['3'] } }
    } }), oauth_headers(User.find(2), scopes: 'view_issues view_issue_watchers')

    assert_response :success
    assert_equal [2], json_body.dig('result', 'structuredContent', 'issues').map { |issue| issue['id'] }
  end

  def test_watcher_filter_can_match_the_caller_without_the_watchers_scope
    Watcher.create!(watchable_type: 'Issue', watchable_id: 1, user_id: 2)

    post_mcp rpc('tools/call', { 'name' => 'search_issues', 'arguments' => {
      'filters' => { 'watcher' => { 'operator' => '=', 'values' => ['me'] } }
    } }), oauth_headers(User.find(2), scopes: 'view_issues')

    assert_response :success
    assert_equal [1], json_body.dig('result', 'structuredContent', 'issues').map { |issue| issue['id'] }
  end

  def test_issue_spent_hours_only_include_visible_time_entries
    Role.update_all(time_entries_visibility: 'own')

    post_mcp rpc('tools/call', { 'name' => 'get_issue',
                               'arguments' => { 'id' => 1, 'include_spent_hours' => true } }),
             api_key_headers(User.find(2))

    assert_response :success
    payload = json_body.dig('result', 'structuredContent')
    assert_equal 4.25, payload['spent_hours'].to_f
    assert_equal 4.25, payload['total_spent_hours'].to_f
  end

  def test_administrators_can_read_all_issue_spent_hours
    Role.update_all(time_entries_visibility: 'own')

    post_mcp rpc('tools/call', { 'name' => 'get_issue',
                               'arguments' => { 'id' => 1, 'include_spent_hours' => true } }),
             api_key_headers(User.find(1))

    assert_response :success
    assert_equal 154.25, json_body.dig('result', 'structuredContent', 'spent_hours').to_f
  end

  def test_spent_time_filter_only_counts_visible_time_entries
    Role.update_all(time_entries_visibility: 'own')
    headers = oauth_headers(User.find(2), scopes: 'view_issues view_time_entries')

    [['=', ['4.25'], [1]], ['>=', ['100'], []], ['<=', ['5'], [1]],
     ['><', ['4', '5'], [1]], ['*', [], [1]], ['!*', [], []]].each do |operator, values, expected|
      post_mcp rpc('tools/call', { 'name' => 'search_issues', 'arguments' => {
        'filters' => { 'issue_id' => { 'operator' => '=', 'values' => ['1'] },
                       'spent_time' => { 'operator' => operator, 'values' => values.presence }.compact }
      } }), headers

      assert_response :success
      assert_equal expected, json_body.dig('result', 'structuredContent', 'issues').map { |issue| issue['id'] }, operator
    end
  end

  def test_spent_time_filter_can_match_all_hours_when_the_role_permits_them
    Role.update_all(time_entries_visibility: 'all')

    post_mcp rpc('tools/call', { 'name' => 'search_issues', 'arguments' => {
      'filters' => { 'issue_id' => { 'operator' => '=', 'values' => ['1'] },
                     'spent_time' => { 'operator' => '>=', 'values' => ['100'] } }
    } }), oauth_headers(User.find(2), scopes: 'view_issues view_time_entries')

    assert_response :success
    assert_equal [1], json_body.dig('result', 'structuredContent', 'issues').map { |issue| issue['id'] }
  end

  def test_spent_time_equality_compares_the_rounded_total
    Role.update_all(time_entries_visibility: 'all')
    entries = TimeEntry.where(issue_id: 1).order(:id).to_a
    assert_operator entries.size, :>=, 2
    entries[0].update_column(:hours, 0.1)
    entries[1].update_column(:hours, 0.2)
    entries.drop(2).each(&:delete)

    post_mcp rpc('tools/call', { 'name' => 'search_issues', 'arguments' => {
      'filters' => { 'issue_id' => { 'operator' => '=', 'values' => ['1'] },
                     'spent_time' => { 'operator' => '=', 'values' => ['0.3'] } }
    } }), oauth_headers(User.find(2), scopes: 'view_issues view_time_entries')

    assert_response :success
    assert_equal [1], json_body.dig('result', 'structuredContent', 'issues').map { |issue| issue['id'] }
  end

  # Redmine's search fetcher cannot apply OAuth narrowing to private notes, so
  # the filter must not be offered while the token hides notes the roles allow.
  def test_full_text_filter_is_withheld_when_the_token_narrows_private_notes
    Role.find(1).add_permission! :view_private_notes
    Journal.find(1).update_columns(private_notes: true, notes: 'Zebracorn secret')

    post_mcp rpc('tools/call', { 'name' => 'search_issues', 'arguments' => {
      'filters' => { 'any_searchable' => { 'operator' => '~', 'values' => ['Zebracorn'] } }
    } }), oauth_headers(User.find(2), scopes: 'view_issues')

    assert_response :success
    assert json_body.dig('result', 'isError')
    assert_match(/Unknown or unavailable issue filter "any_searchable"/, json_body['result']['content'].first['text'])
  end

  def test_full_text_filter_matches_private_notes_with_the_oauth_scope
    Role.find(1).add_permission! :view_private_notes
    Journal.find(1).update_columns(private_notes: true, notes: 'Zebracorn secret')

    post_mcp rpc('tools/call', { 'name' => 'search_issues', 'arguments' => {
      'filters' => { 'any_searchable' => { 'operator' => '~', 'values' => ['Zebracorn'] } }
    } }), oauth_headers(User.find(2), scopes: 'view_issues view_private_notes')

    assert_response :success
    assert_equal [1], json_body.dig('result', 'structuredContent', 'issues').map { |issue| issue['id'] }
  end

  def test_full_text_filter_stays_available_when_roles_already_hide_private_notes
    Role.all.each { |role| role.remove_permission! :view_private_notes }
    Journal.find(1).update_columns(private_notes: true, notes: 'Zebracorn secret')
    Journal.find(2).update_columns(private_notes: false, notes: 'Quokka public')
    headers = oauth_headers(User.find(2), scopes: 'view_issues')

    { 'Zebracorn' => [], 'Quokka' => [1] }.each do |word, expected|
      post_mcp rpc('tools/call', { 'name' => 'search_issues', 'arguments' => {
        'filters' => { 'any_searchable' => { 'operator' => '~', 'values' => [word] } }
      } }), headers

      assert_response :success
      assert_equal expected, json_body.dig('result', 'structuredContent', 'issues').map { |issue| issue['id'] }, word
    end
  end

  def test_history_operators_ignore_private_journals_without_the_oauth_scope
    Role.find(1).add_permission! :view_private_notes
    Journal.find(1).update_column(:private_notes, true)
    Issue.find(1).update_column(:status_id, 3)
    headers = oauth_headers(User.find(2), scopes: 'view_issues')

    { 'cf' => [], 'ev' => [], '!ev' => [1] }.each do |operator, expected|
      post_mcp rpc('tools/call', { 'name' => 'search_issues', 'arguments' => {
        'filters' => { 'issue_id' => { 'operator' => '=', 'values' => ['1'] },
                       'status_id' => { 'operator' => operator, 'values' => ['1'] } }
      } }), headers

      assert_response :success
      assert_equal expected, json_body.dig('result', 'structuredContent', 'issues').map { |issue| issue['id'] }, operator
    end
  end

  def test_history_operators_match_private_journals_with_the_oauth_scope
    Role.find(1).add_permission! :view_private_notes
    Journal.find(1).update_column(:private_notes, true)
    Issue.find(1).update_column(:status_id, 3)
    headers = oauth_headers(User.find(2), scopes: 'view_issues view_private_notes')

    { 'cf' => [1], 'ev' => [1], '!ev' => [] }.each do |operator, expected|
      post_mcp rpc('tools/call', { 'name' => 'search_issues', 'arguments' => {
        'filters' => { 'issue_id' => { 'operator' => '=', 'values' => ['1'] },
                       'status_id' => { 'operator' => operator, 'values' => ['1'] } }
      } }), headers

      assert_response :success
      assert_equal expected, json_body.dig('result', 'structuredContent', 'issues').map { |issue| issue['id'] }, operator
    end
  end

  def test_has_been_operator_still_matches_the_current_value
    post_mcp rpc('tools/call', { 'name' => 'search_issues', 'arguments' => {
      'filters' => { 'issue_id' => { 'operator' => '=', 'values' => ['1'] },
                     'status_id' => { 'operator' => 'ev', 'values' => ['1'] } }
    } }), oauth_headers(User.find(2), scopes: 'view_issues')

    assert_response :success
    assert_equal [1], json_body.dig('result', 'structuredContent', 'issues').map { |issue| issue['id'] }
  end

  def test_version_time_totals_only_include_visible_records
    Role.update_all(time_entries_visibility: 'own', issues_visibility: 'default')
    version = Version.create!(project: Project.find(1), name: 'Visibility test')
    Issue.find(1).update_columns(fixed_version_id: version.id, estimated_hours: 10)
    Issue.find(3).update_columns(fixed_version_id: version.id, estimated_hours: 90,
                                 is_private: true, author_id: 1, assigned_to_id: 1)
    assert_not Issue.find(3).visible?(User.find(2))

    post_mcp rpc('tools/call', { 'name' => 'list_versions',
                               'arguments' => { 'project' => 'ecookbook', 'include_time_totals' => true } }),
             oauth_headers(User.find(2), scopes: 'view_issues view_time_entries')

    assert_response :success
    item = json_body.dig('result', 'structuredContent', 'versions').find { |row| row['id'] == version.id }
    assert_not_nil item
    assert_equal 10, item['estimated_hours'].to_f
    assert_equal 4.25, item['spent_hours'].to_f
  end

  def test_malformed_json_is_a_parse_error
    post_mcp '{not json', api_key_headers(User.find(2))
    assert_response :bad_request
    assert_equal RedmineMcp::JsonRpc::PARSE_ERROR, json_body['error']['code']
  end

  def test_authentication_precedes_json_rpc_parsing
    post_mcp '{not json'

    assert_response :unauthorized
    assert_equal 'Authentication failed', json_body['error']
  end

  def test_batches_are_refused
    post_mcp [{ jsonrpc: '2.0', id: 1, method: 'tools/list' }].to_json, api_key_headers(User.find(2))
    assert_response :bad_request
    assert_equal RedmineMcp::JsonRpc::INVALID_REQUEST, json_body['error']['code']
  end

  def test_notification_gets_202_with_no_body
    post_mcp({ jsonrpc: '2.0', method: 'notifications/initialized' }.to_json, api_key_headers(User.find(2)))
    assert_response :accepted
    assert response.body.blank?
  end

  def test_unsupported_protocol_version_is_a_400
    post_mcp rpc('tools/list'), api_key_headers(User.find(2)).merge('MCP-Protocol-Version' => '1999-01-01')
    assert_response :bad_request
    assert_equal RedmineMcp::JsonRpc::UNSUPPORTED_PROTOCOL_VERSION, json_body['error']['code']
  end

  def test_get_returns_405_because_there_is_no_stream
    @request.headers.merge!(api_key_headers(User.find(2)))
    get :stream
    assert_response :method_not_allowed
  end

  def test_unknown_method_is_method_not_found
    post_mcp rpc('nonsense/method'), api_key_headers(User.find(2))
    assert_equal JsonRpcHandler::ErrorCode::METHOD_NOT_FOUND, json_body['error']['code']
  end

  def test_foreign_origin_is_rejected
    post_mcp rpc('tools/list'), api_key_headers(User.find(2)).merge('Origin' => 'https://evil.example')
    assert_response :forbidden
  end

  def test_foreign_origin_is_rejected_before_authentication
    post_mcp rpc('tools/list'), 'Origin' => 'https://evil.example'

    assert_response :forbidden
    assert_equal 'Origin not allowed', json_body['error']
  end

  def test_configured_origin_is_allowed
    enable_mcp('allowed_origins' => 'https://friend.example')
    post_mcp rpc('tools/list'), api_key_headers(User.find(2)).merge('Origin' => 'https://friend.example')
    assert_response :success
  end

  def test_absent_origin_is_allowed
    post_mcp rpc('tools/list'), api_key_headers(User.find(2))
    assert_response :success
  end

  def test_server_discover_advertises_versions
    post_mcp rpc('server/discover'), api_key_headers(User.find(2))
    assert_response :success
    assert_equal ['2026-07-28'], json_body['result']['supportedVersions']
  end

  def test_initialize_echoes_supported_handshake_version
    post_mcp rpc('initialize', initialize_params('2025-06-18')), api_key_headers(User.find(2))
    assert_equal '2025-06-18', json_body['result']['protocolVersion']
  end

  def test_initialize_counteroffers_a_handshake_version_for_a_modern_version
    post_mcp rpc('initialize', initialize_params('2026-07-28')), api_key_headers(User.find(2))

    assert_equal '2025-11-25', json_body['result']['protocolVersion']
  end

  def test_server_protocol_state_is_isolated_per_request
    headers = api_key_headers(User.find(2))
    payload = rpc('initialize', initialize_params('2025-11-25'))

    2.times do
      post_mcp payload, headers
      assert_equal '2025-11-25', json_body.dig('result', 'protocolVersion')
    end
  end

  def test_legacy_tools_list_has_no_modern_result_or_cache_metadata
    post_mcp rpc('tools/list'), api_key_headers(User.find(2))
    result = json_body['result']

    assert_not result.key?('resultType')
    assert_not result.key?('_meta')
    assert_not result.key?('cacheScope')
    assert_not result.key?('ttlMs')
  end

  def test_write_tools_are_hidden_in_read_only_mode
    post_mcp rpc('tools/list'), api_key_headers(User.find(1))
    names = json_body['result']['tools'].pluck('name')
    assert_not_includes names, 'create_issue'
    assert_includes names, 'search_issues'
  end

  def test_write_tool_call_is_refused_in_read_only_mode
    post_mcp rpc('tools/call', { 'name' => 'create_issue',
                                 'arguments' => { 'project' => 'ecookbook', 'subject' => 'x' } }),
             oauth_headers(User.find(2), scopes: 'view_issues')
    assert_response :forbidden
    assert_nil response.headers['WWW-Authenticate']
  end

  def test_unknown_tool_remains_an_sdk_not_found_error
    post_mcp rpc('tools/call', { 'name' => 'not_registered', 'arguments' => {} }),
             api_key_headers(User.find(1))

    assert_equal(-32_602, json_body.dig('error', 'code'))
    assert_equal 'Invalid params', json_body.dig('error', 'message')
    assert_equal 'Tool not found: not_registered', json_body.dig('error', 'data')
  end

  def test_write_tools_appear_when_read_only_is_off
    enable_mcp('read_only' => '0')
    post_mcp rpc('tools/list'), api_key_headers(User.find(1))
    assert_includes json_body['result']['tools'].pluck('name'), 'create_issue'
  end

  def test_update_issue_changes_fields
    # A write tool, so read-only mode -- which is on by default -- has to be
    # switched off first.
    enable_mcp('read_only' => '0')
    issue = Issue.find(1)
    assignee = issue.project.assignable_users.first
    post_mcp rpc('tools/call', { 'name' => 'update_issue',
                                 'arguments' => {
                                   'id' => issue.id,
                                   'subject' => 'Updated issue title',
                                   'status' => 'Closed',
                                   'done_ratio' => 100,
                                   'priority' => 'Urgent',
                                   'assigned_to' => assignee.login
                                 } }),
             api_key_headers(User.find(1))

    assert_response :success
    assert_equal 'Updated issue title', json_body['result']['structuredContent']['subject']
    assert_equal 'Closed', json_body['result']['structuredContent']['status']
    assert_equal 100, json_body['result']['structuredContent']['done_ratio']
    assert_equal assignee.login, User.find(json_body['result']['structuredContent']['assigned_to_id']).login
  end

  # Without a current journal Redmine records no history, so a field change
  # with no notes used to leave the issue's history silent.
  def test_update_issue_without_notes_records_history
    enable_mcp('read_only' => '0')
    issue = Issue.find(1)
    old_subject = issue.subject

    assert_difference -> { issue.journals.count }, 1 do
      post_mcp rpc('tools/call', { 'name' => 'update_issue',
                                   'arguments' => { 'id' => issue.id, 'subject' => 'Renamed without notes' } }),
               api_key_headers(User.find(1))
    end

    assert_response :success
    assert_not json_body['result']['isError']
    journal = issue.journals.order(:id).last
    assert_equal User.find(1), journal.user
    detail = journal.details.find_by(property: 'attr', prop_key: 'subject')
    assert_equal [old_subject, 'Renamed without notes'], [detail.old_value, detail.value]
  end

  def test_update_issue_without_changes_records_no_empty_history
    enable_mcp('read_only' => '0')
    issue = Issue.find(1)

    assert_no_difference -> { issue.journals.count } do
      post_mcp rpc('tools/call', { 'name' => 'update_issue',
                                   'arguments' => { 'id' => issue.id, 'subject' => issue.subject } }),
               api_key_headers(User.find(1))
    end
    assert_not json_body['result']['isError']
  end

  # --- assignment ---------------------------------------------------------

  # A Group is a Principal with no login, so `assigned_to` could never resolve
  # to one while the lookup went through `find_by(login:)`. Whether a group is
  # eligible at all stays core's decision, not the plugin's:
  # Project#assignable_users only adds 'Group' to its types while
  # Setting.issue_group_assignment is on, which is what the next test pins.
  def test_update_issue_assigns_to_a_group
    enable_mcp('read_only' => '0')
    Setting.issue_group_assignment = '1'
    # Fixture group 11 ('B Team') is a Developer member of project 2.
    post_mcp rpc('tools/call', { 'name' => 'update_issue',
                                 'arguments' => { 'id' => 4, 'assigned_to' => 'B Team' } }),
             api_key_headers(User.find(1))

    assert_response :success
    assert_equal 11, json_body['result']['structuredContent']['assigned_to_id']
    assert_equal 11, Issue.find(4).assigned_to_id
  end

  # The plugin must not invent a second policy: with the core setting off, a
  # group is not in Project#assignable_users and the call is refused.
  def test_group_assignment_is_refused_while_core_disallows_it
    enable_mcp('read_only' => '0')
    Setting.issue_group_assignment = '0'
    post_mcp rpc('tools/call', { 'name' => 'update_issue',
                                 'arguments' => { 'id' => 4, 'assigned_to' => 'B Team' } }),
             api_key_headers(User.find(1))

    assert json_body['result']['isError']
    assert_match(/not an assignable user or group/, json_body['result']['content'].first['text'])
    assert_equal 2, Issue.find(4).assigned_to_id
  end

  def test_create_issue_assigns_to_a_group
    enable_mcp('read_only' => '0')
    Setting.issue_group_assignment = '1'
    post_mcp rpc('tools/call', { 'name' => 'create_issue',
                                 'arguments' => { 'project' => 'onlinestore',
                                                  'subject' => 'Work for the team',
                                                  'assigned_to' => 'B Team' } }),
             api_key_headers(User.find(1))

    assert_response :success
    created = Issue.find(json_body['result']['structuredContent']['id'])
    assert_equal 11, created.assigned_to_id
  end

  # --- time entries -------------------------------------------------------

  def test_create_time_entry_logs_time_as_the_caller
    enable_mcp('read_only' => '0')
    user = User.find(2)
    assert_difference 'TimeEntry.count', 1 do
      post_mcp rpc('tools/call', { 'name' => 'create_time_entry',
                                   'arguments' => { 'issue_id' => 1, 'hours' => 1.5,
                                                    'spent_on' => '2026-09-24', 'comments' => 'Review' } }),
               api_key_headers(user)
    end

    payload = json_body['result']['structuredContent']
    assert_equal 1, payload['issue_id']
    assert_equal '2026-09-24', payload['spent_on']
    assert_equal user.id, TimeEntry.find(payload['id']).user_id
  end

  def test_create_time_entry_needs_an_issue_or_a_project
    enable_mcp('read_only' => '0')
    post_mcp rpc('tools/call', { 'name' => 'create_time_entry', 'arguments' => { 'hours' => 1 } }),
             api_key_headers(User.find(2))
    assert json_body['result']['isError']
  end

  # In project 1 jsmith is a Manager: edit_time_entries without
  # edit_own_time_entries. Core counts that as enough for an own entry.
  def test_update_time_entry_changes_own_entry
    enable_mcp('read_only' => '0')
    user = User.find(2)
    time_entry = TimeEntry.where(user_id: user.id).first
    post_mcp rpc('tools/call', { 'name' => 'update_time_entry',
                                 'arguments' => { 'id' => time_entry.id, 'hours' => 2.5, 'comments' => 'Edited' } }),
             api_key_headers(user)

    assert_equal 2.5, json_body['result']['structuredContent']['hours']
    assert_equal 'Edited', time_entry.reload.comments
  end

  # Somebody else's entry gets the same refusal as a missing one.
  def test_update_time_entry_refuses_another_users_entry
    enable_mcp('read_only' => '0')
    user = User.find(2)
    time_entry = TimeEntry.where.not(user_id: user.id).first
    post_mcp rpc('tools/call', { 'name' => 'update_time_entry', 'arguments' => { 'id' => time_entry.id, 'hours' => 1 } }),
             api_key_headers(user)

    assert json_body['result']['isError']
    assert_match(/No time entry of yours/, json_body['result']['content'].first['text'])
  end

  def test_delete_time_entry_removes_own_entry
    enable_mcp('read_only' => '0')
    user = User.find(2)
    time_entry = TimeEntry.where(user_id: user.id).first
    assert_difference 'TimeEntry.count', -1 do
      post_mcp rpc('tools/call', { 'name' => 'delete_time_entry', 'arguments' => { 'id' => time_entry.id } }),
               api_key_headers(user)
    end
    assert json_body['result']['structuredContent']['deleted']
  end

  def test_list_time_entries_only_returns_visible_rows
    user = User.find(2)
    post_mcp rpc('tools/call', { 'name' => 'list_time_entries' }), api_key_headers(user)
    assert_equal TimeEntry.visible(user).count, json_body['result']['structuredContent']['total_count']
  end

  # --- visibility ---------------------------------------------------------

  def test_whoami_reports_the_authenticated_user
    post_mcp rpc('tools/call', { 'name' => 'whoami' }), api_key_headers(User.find(2))
    payload = json_body['result']['structuredContent']
    assert_equal 2, payload['id']
    assert_equal 'api_key', payload['authentication_mode']
    assert_nil payload['oauth_scopes']
  end

  def test_oauth_scope_does_not_hide_tools_permitted_by_the_users_role
    user = User.find(2)

    post_mcp rpc('tools/list'), api_key_headers(user)
    api_key_tools = json_body['result']['tools'].pluck('name')
    assert_includes api_key_tools, 'list_projects'
    assert_includes api_key_tools, 'search_issues'

    oauth = oauth_headers(user, scopes: 'view_issues')
    post_mcp rpc('tools/list'), oauth
    oauth_tools = json_body['result']['tools'].pluck('name')
    assert_includes oauth_tools, 'whoami'
    assert_includes oauth_tools, 'list_users'
    assert_includes oauth_tools, 'list_enumerations'
    assert_includes oauth_tools, 'list_projects'
    assert_includes oauth_tools, 'search_issues'

    post_mcp rpc('tools/call', { 'name' => 'search_issues' }), oauth
    assert_not json_body.dig('result', 'isError')
  end

  def test_read_scope_challenge_never_includes_write_scopes
    oauth = oauth_headers(User.find(2), scopes: 'view_issues')

    post_mcp rpc('tools/call', { 'name' => 'list_projects' }), oauth

    assert_response :forbidden
    # view_project correlates one hop to its same-tier reads; the challenge stays
    # entirely within the read tier and never introduces a write scope.
    assert_equal(
      'Bearer error="insufficient_scope", scope="view_project view_issues view_wiki_pages", ' \
      'resource_metadata="http://test.host/.well-known/oauth-protected-resource/mcp", ' \
      'error_description="The access token lacks the scope required for this operation"',
      response.headers['WWW-Authenticate']
    )
  end

  def test_issue_creation_challenge_includes_all_same_tier_correlated_scopes
    enable_mcp('read_only' => '0')
    oauth = oauth_headers(User.find(2), scopes: 'view_issues')

    post_mcp rpc('tools/call', { 'name' => 'create_issue',
                                 'arguments' => { 'project' => 'ecookbook', 'subject' => 'x' } }), oauth

    assert_response :forbidden
    assert_equal(
      'Bearer error="insufficient_scope", scope="add_issues add_issue_notes", ' \
      'resource_metadata="http://test.host/.well-known/oauth-protected-resource/mcp", ' \
      'error_description="The access token lacks the scope required for this operation"',
      response.headers['WWW-Authenticate']
    )
  end

  # list_issue_custom_fields reads but is gated on add_issues, so a narrow
  # token must get a write-tier challenge rather than a 500.
  def test_read_tool_gated_on_a_write_permission_gets_a_write_tier_challenge
    oauth = oauth_headers(User.find(2), scopes: 'view_issues view_project')

    post_mcp rpc('tools/call', { 'name' => 'list_issue_custom_fields',
                                 'arguments' => { 'project' => 'ecookbook' } }), oauth

    assert_response :forbidden
    assert_equal(
      'Bearer error="insufficient_scope", scope="add_issues add_issue_notes", ' \
      'resource_metadata="http://test.host/.well-known/oauth-protected-resource/mcp", ' \
      'error_description="The access token lacks the scope required for this operation"',
      response.headers['WWW-Authenticate']
    )
  end

  def test_private_issue_note_challenge_includes_every_required_scope
    enable_mcp('read_only' => '0')
    oauth = oauth_headers(User.find(2), scopes: 'add_issue_notes')

    post_mcp rpc('tools/call', { 'name' => 'add_issue_note',
                                 'arguments' => { 'id' => 1, 'notes' => 'Private', 'private' => true } }), oauth

    assert_response :forbidden
    assert_equal(
      'Bearer error="insufficient_scope", scope="add_issue_notes set_notes_private", ' \
      'resource_metadata="http://test.host/.well-known/oauth-protected-resource/mcp", ' \
      'error_description="The access token lacks the scope required for this operation"',
      response.headers['WWW-Authenticate']
    )
  end

  def test_oauth_administrator_without_a_grantable_role_is_challenged_for_admin
    enable_mcp('read_only' => '0')
    administrator = User.find(4)
    administrator.update_columns(admin: true)
    assert_not administrator.roles.any? { |role| role.allowed_to?(:set_notes_private) }
    assert_not administrator.builtin_role.allowed_to?(:set_notes_private)

    post_mcp rpc('tools/call', { 'name' => 'add_issue_note',
                                 'arguments' => { 'id' => 1, 'notes' => 'Private', 'private' => true } }),
             oauth_headers(administrator, scopes: 'view_issues')

    assert_response :forbidden
    assert_equal(
      'Bearer error="insufficient_scope", scope="admin", ' \
      'resource_metadata="http://test.host/.well-known/oauth-protected-resource/mcp", ' \
      'error_description="The access token lacks the scope required for this operation"',
      response.headers['WWW-Authenticate']
    )

    post_mcp rpc('tools/call', { 'name' => 'add_issue_note',
                                 'arguments' => { 'id' => 1, 'notes' => 'Authorized', 'private' => true } }),
             oauth_headers(administrator, scopes: 'admin')
    assert_response :success
    assert_not json_body.dig('result', 'isError')
  end

  def test_admin_only_read_authorization_does_not_challenge_for_write_tier_admin
    Role.non_member.remove_permission!(:view_wiki_pages)
    administrator = User.find(4)
    administrator.update_columns(admin: true)
    assert_not administrator.roles.any? { |role| role.allowed_to?(:view_wiki_pages) }

    post_mcp rpc('tools/call', { 'name' => 'list_wiki_pages' }),
             oauth_headers(administrator, scopes: 'view_issues')

    assert_response :forbidden
    assert_nil response.headers['WWW-Authenticate']
  end

  def test_oauth_scope_does_not_expose_tools_denied_by_the_users_role
    Role.non_member.remove_permission!(:view_wiki_pages)
    oauth = oauth_headers(User.find(7), scopes: 'view_wiki_pages')

    post_mcp rpc('tools/list'), oauth
    assert_not_includes json_body['result']['tools'].pluck('name'), 'list_wiki_pages'

    post_mcp rpc('tools/call', { 'name' => 'list_wiki_pages' }), oauth
    assert_response :forbidden
    assert_nil response.headers['WWW-Authenticate']
  end

  def test_permissionless_tools_need_no_oauth_scope
    post_mcp rpc('tools/list'), oauth_headers(User.find(2), scopes: '')

    names = json_body['result']['tools'].pluck('name')
    assert_includes names, 'whoami'
    assert_includes names, 'list_users'
    assert_includes names, 'list_enumerations'
  end

  def test_sdk_schema_failure_is_an_error_tool_result
    post_mcp rpc('tools/call', { 'name' => 'get_project', 'arguments' => {} }),
             api_key_headers(User.find(2))

    assert json_body.dig('result', 'isError')
    assert_equal 'Missing required arguments: project', json_body.dig('result', 'content', 0, 'text')
  end

  def test_unexpected_tool_exception_does_not_leak_internal_details
    secret = 'private-database-detail-/var/redmine'
    Issue.stubs(:visible).raises(StandardError, secret)

    post_mcp rpc('tools/call', { 'name' => 'get_issue', 'arguments' => { 'id' => 1 } }),
             api_key_headers(User.find(2))

    assert_equal(-32_603, json_body.dig('error', 'code'))
    assert_equal 'Internal error', json_body.dig('error', 'message')
    assert_equal 'Internal error calling tool get_issue', json_body.dig('error', 'data')
    assert_not_includes response.body, secret
  end

  def test_control_characters_are_not_rejected_at_the_mcp_boundary
    post_mcp rpc('tools/call', { 'name' => 'search_issues', 'arguments' => { 'query' => "a\u0007b" } }),
             api_key_headers(User.find(2))

    assert_not json_body.dig('result', 'isError')
  end

  # Keep invisible and nonexistent issues indistinguishable to prevent record
  # existence from leaking through error text.
  def test_invisible_issue_is_reported_as_not_found
    issue = Issue.find(4)
    issue.update_columns(is_private: true)
    post_mcp rpc('tools/call', { 'name' => 'get_issue', 'arguments' => { 'id' => issue.id } }),
             api_key_headers(User.find(7))
    assert_response :success
    assert json_body['result']['isError']
    assert_match(/No visible issue/, json_body['result']['content'].first['text'])
  end

  def test_search_issues_only_returns_visible_rows
    user = User.find(7)
    post_mcp rpc('tools/call', { 'name' => 'search_issues', 'arguments' => { 'status' => 'all' } }),
             api_key_headers(user)
    returned = json_body['result']['structuredContent']['issues'].pluck('id')
    assert_equal returned.sort, Issue.visible(user).where(id: returned).pluck(:id).sort
    assert Issue.count > returned.size, 'fixture set should be larger than what one user can see'
  end

  def test_list_users_respects_users_visibility
    user = User.find(7)
    post_mcp rpc('tools/call', { 'name' => 'list_users' }), api_key_headers(user)
    total = json_body['result']['structuredContent']['total_count']
    assert_equal Principal.visible(user).where(type: 'User').active.count, total
  end

  def test_create_issue_sets_parent_category_and_version
    enable_mcp('read_only' => '0')
    parent = Issue.find(1)
    category = parent.project.issue_categories.first
    version = parent.assignable_versions.first
    post_mcp rpc('tools/call', { 'name' => 'create_issue',
                                 'arguments' => {
                                   'project' => parent.project.identifier,
                                   'subject' => 'Child issue',
                                   'parent_issue_id' => parent.id,
                                   'category' => category.name,
                                   'fixed_version' => version.name
                                 } }),
             api_key_headers(User.find(1))

    assert_response :success
    result = json_body['result']['structuredContent']
    assert_equal parent.id, result['parent_id']
    assert_equal category.name, result['category']
    assert_equal version.name, result['fixed_version']
  end

  def test_create_issue_rejects_unknown_category
    enable_mcp('read_only' => '0')
    post_mcp rpc('tools/call', { 'name' => 'create_issue',
                                 'arguments' => { 'project' => 'ecookbook', 'subject' => 'x',
                                                  'category' => 'No such category' } }),
             api_key_headers(User.find(1))

    assert json_body['result']['isError']
    assert_equal 0, Issue.where(subject: 'x').count
  end

  def test_update_issue_clears_parent_with_none
    enable_mcp('read_only' => '0')
    child = Issue.generate!(project_id: 1, parent_issue_id: 1)
    post_mcp rpc('tools/call', { 'name' => 'update_issue',
                                 'arguments' => { 'id' => child.id, 'parent_issue_id' => 'none' } }),
             api_key_headers(User.find(1))

    assert_response :success
    assert_nil child.reload.parent_id
  end

  def test_add_issue_relation_links_issues_and_get_issue_reports_it
    enable_mcp('read_only' => '0')
    post_mcp rpc('tools/call', { 'name' => 'add_issue_relation',
                                 'arguments' => { 'issue_id' => 1, 'issue_to_id' => 2, 'relation_type' => 'blocks' } }),
             api_key_headers(User.find(1))

    assert_response :success
    assert IssueRelation.exists?(issue_from_id: 1, issue_to_id: 2, relation_type: 'blocks')

    post_mcp rpc('tools/call', { 'name' => 'get_issue', 'arguments' => { 'id' => 2, 'include_journals' => false, 'include_relations' => true } }),
             api_key_headers(User.find(1))
    relations = json_body['result']['structuredContent']['relations']
    assert_includes relations.map { |r| [r['issue_id'], r['type']] }, [1, 'blocked']
  end

  def test_add_issue_relation_refuses_an_existing_link_asked_in_reverse
    enable_mcp('read_only' => '0')
    IssueRelation.create!(issue_from: Issue.find(1), issue_to: Issue.find(3), relation_type: 'blocks')
    post_mcp rpc('tools/call', { 'name' => 'add_issue_relation',
                                 'arguments' => { 'issue_id' => 3, 'issue_to_id' => 1, 'relation_type' => 'blocked' } }),
             api_key_headers(User.find(1))

    assert json_body['result']['isError']
    assert_match(/already related/, json_body['result']['content'].first['text'])
  end

  def test_update_issue_refuses_a_status_the_workflow_does_not_allow
    enable_mcp('read_only' => '0')
    # Core fixtures let the Manager role reach every status; take Closed away.
    WorkflowTransition.where(role_id: 1, new_status_id: IssueStatus.find_by(name: 'Closed').id).delete_all
    issue = Issue.find(1)
    post_mcp rpc('tools/call', { 'name' => 'update_issue', 'arguments' => { 'id' => issue.id, 'status' => 'Closed' } }),
             api_key_headers(User.find(2))

    assert json_body['result']['isError']
    assert_not_equal 'Closed', issue.reload.status.name
  end

  def test_parent_needs_manage_subtasks
    enable_mcp('read_only' => '0')
    Role.find(1).remove_permission!(:manage_subtasks)
    post_mcp rpc('tools/call', { 'name' => 'update_issue', 'arguments' => { 'id' => 2, 'parent_issue_id' => 1 } }),
             api_key_headers(User.find(2))

    assert json_body['result']['isError']
    assert_nil Issue.find(2).parent_id
  end

  def test_search_issues_defaults_to_all_statuses
    user = User.find(2)
    visible = Issue.visible(user)
    closed_count = visible.joins(:status).where(issue_statuses: { is_closed: true }).count
    assert closed_count.positive?, 'fixture set should contain at least one visible closed issue'

    post_mcp rpc('tools/call', { 'name' => 'search_issues', 'arguments' => {} }), api_key_headers(user)

    payload = json_body['result']['structuredContent']
    returned_ids = payload['issues'].map { |issue| issue['id'] }
    assert Issue.where(id: returned_ids).joins(:status).where(issue_statuses: { is_closed: true }).any?
    assert_equal visible.count, payload['total_count']
  end

  def test_search_issues_can_filter_by_author_display_name
    user = User.find(2)
    issue = Issue.visible(user).where.not(author_id: nil).first
    assert_not_nil issue, 'fixture set should contain at least one visible issue with an author'
    author = issue.author
    expected = Issue.visible(user).where(author_id: author.id)

    arguments = {
      'filters' => {
        'author' => { 'operator' => '=', 'values' => [author.name.swapcase] }
      }
    }
    post_mcp rpc('tools/call', { 'name' => 'search_issues', 'arguments' => arguments }), api_key_headers(user)

    payload = json_body['result']['structuredContent']
    returned_ids = payload['issues'].map { |result| result['id'] }
    assert returned_ids.any?
    assert_equal [author.id], Issue.where(id: returned_ids).distinct.pluck(:author_id)
    assert_equal expected.count, payload['total_count']
  end

  def test_search_issues_can_filter_by_author_login
    user = User.find(2)
    issue = Issue.visible(user).where(author_id: User.where.not(login: '').select(:id)).first
    assert_not_nil issue, 'fixture set should contain at least one visible issue with an author login'
    author = issue.author
    expected = Issue.visible(user).where(author_id: author.id)

    arguments = {
      'filters' => {
        'author' => { 'operator' => '=', 'values' => [author.login.swapcase] }
      }
    }
    post_mcp rpc('tools/call', { 'name' => 'search_issues', 'arguments' => arguments }), api_key_headers(user)

    payload = json_body['result']['structuredContent']
    returned_ids = payload['issues'].map { |result| result['id'] }
    assert returned_ids.any?
    assert_equal [author.id], Issue.where(id: returned_ids).distinct.pluck(:author_id)
    assert_equal expected.count, payload['total_count']
  end

  def test_search_issues_can_filter_by_author_id
    user = User.find(2)
    author_id = Issue.visible(user).where.not(author_id: nil).pick(:author_id)
    assert_not_nil author_id

    arguments = {
      'filters' => {
        'author_id' => { 'operator' => '=', 'values' => [author_id.to_s] }
      }
    }
    post_mcp rpc('tools/call', { 'name' => 'search_issues', 'arguments' => arguments }), api_key_headers(user)

    payload = json_body['result']['structuredContent']
    returned_ids = payload['issues'].map { |issue| issue['id'] }
    assert returned_ids.any?
    assert_equal [author_id], Issue.where(id: returned_ids).distinct.pluck(:author_id)
    assert_equal Issue.visible(user).where(author_id: author_id).count, payload['total_count']
  end

  def test_search_issues_named_status_supports_open_operator_without_values
    user = User.find(2)
    arguments = { 'filters' => { 'status' => { 'operator' => 'o' } } }
    post_mcp rpc('tools/call', { 'name' => 'search_issues', 'arguments' => arguments }), api_key_headers(user)

    payload = json_body['result']['structuredContent']
    returned_ids = payload['issues'].map { |issue| issue['id'] }
    assert Issue.where(id: returned_ids).joins(:status).where(issue_statuses: { is_closed: true }).none?
    assert_equal Issue.visible(user).open.count, payload['total_count']
  end

  def test_search_issues_rejects_named_and_native_forms_of_same_filter
    user = User.find(2)
    arguments = {
      'filters' => {
        'author' => { 'operator' => '=', 'values' => [user.name] },
        'author_id' => { 'operator' => '=', 'values' => [user.id.to_s] }
      }
    }
    post_mcp rpc('tools/call', { 'name' => 'search_issues', 'arguments' => arguments }), api_key_headers(user)

    assert json_body['result']['isError']
    assert_match(/both refer to "author_id"/, json_body['result']['content'].first['text'])
  end

  def test_search_issues_rejects_unknown_named_filter_value
    arguments = {
      'filters' => {
        'tracker' => { 'operator' => '=', 'values' => ['definitely-not-a-real-tracker'] }
      }
    }
    post_mcp rpc('tools/call', { 'name' => 'search_issues', 'arguments' => arguments }), api_key_headers(User.find(2))

    assert json_body['result']['isError']
    assert_match(/Unknown value/, json_body['result']['content'].first['text'])
  end

  def test_search_issues_rejects_unknown_redmine_filter
    arguments = {
      'filters' => {
        'definitely_not_a_filter' => { 'operator' => '=', 'values' => ['1'] }
      }
    }
    post_mcp rpc('tools/call', { 'name' => 'search_issues', 'arguments' => arguments }), api_key_headers(User.find(2))

    assert json_body['result']['isError']
    assert_match(/Unknown or unavailable issue filter/, json_body['result']['content'].first['text'])
  end

  def test_search_issues_filters_are_validated_against_json_schema
    user = User.find(2)

    cases = [
      [
        { 'filters' => [] },
        /filters must be an object/
      ],
      [
        {
          'filters' => {
            'author' => { 'values' => ['John Smith'] }
          }
        },
        /Missing required argument in filters\.author: operator/
      ],
      [
        {
          'filters' => {
            'author_id' => { 'operator' => '=', 'values' => '2' }
          }
        },
        /filters\.author_id\.values must be an array/
      ],
      [
        {
          'filters' => {
            'author_id' => {
              'operator' => '=',
              'values' => ['2'],
              'unexpected' => true
            }
          }
        },
        /Unknown argument in filters\.author_id: "unexpected"/
      ],
      [
        {
          'filters' => {
            'author_id' => {
              'operator' => '=',
              'values' => [{ 'id' => 2 }]
            }
          }
        },
        /filters\.author_id\.values\[0\] must be/
      ]
    ]

    cases.each do |arguments, expected_error|
      post_mcp(
        rpc('tools/call', {
              'name' => 'search_issues',
              'arguments' => arguments
            }),
        api_key_headers(user)
      )

      result = json_body['result']

      assert result['isError'],
            "Expected #{arguments.inspect} to be rejected"
      assert_match(/Invalid arguments:/, result['content'].first['text'])
    end
  end

  def test_new_write_tools_are_hidden_and_refused_in_read_only_mode
    names = %w[update_issue add_issue_relation create_time_entry update_time_entry delete_time_entry]
    post_mcp rpc('tools/list'), api_key_headers(User.find(1))
    assert_empty names & json_body['result']['tools'].pluck('name')
    names.each do |name|
      post_mcp rpc('tools/call', { 'name' => name, 'arguments' => {} }), api_key_headers(User.find(1))
      assert_response :forbidden
    end
  end

  def test_new_write_tools_offer_an_oauth_scope_challenge
    enable_mcp('read_only' => '0')
    user = User.find(2)
    {
      'update_issue' => 'edit_issues',
      'add_issue_relation' => 'manage_issue_relations',
      'create_time_entry' => 'log_time',
      'update_time_entry' => 'edit_time_entries',
      'delete_time_entry' => 'edit_time_entries'
    }.each do |name, permission|
      post_mcp rpc('tools/call', { 'name' => name, 'arguments' => {} }), oauth_headers(user, scopes: 'view_issues')
      assert_response :forbidden
      if name.end_with?('time_entry') && name != 'create_time_entry'
        assert_match(/scope="edit_(own_)?time_entries"/, response.headers['WWW-Authenticate'])
      else
        assert_includes response.headers['WWW-Authenticate'], "scope=\"#{permission}\""
      end
    end
  end

  def test_oauth_time_edit_accepts_the_broader_edit_permission
    enable_mcp('read_only' => '0')
    user = User.find(2)
    entry = TimeEntry.where(user_id: user.id).first
    post_mcp rpc('tools/call', { 'name' => 'update_time_entry',
                                 'arguments' => { 'id' => entry.id, 'comments' => 'OAuth edit' } }),
             oauth_headers(user, scopes: 'view_time_entries edit_time_entries')
    assert_response :success
    assert_not json_body['result']['isError']
    assert_equal 'OAuth edit', entry.reload.comments
  end

  def test_private_update_note_requires_its_own_oauth_scope
    enable_mcp('read_only' => '0')
    post_mcp rpc('tools/call', { 'name' => 'update_issue',
                                 'arguments' => { 'id' => 1, 'notes' => 'Private update', 'private' => true } }),
             oauth_headers(User.find(2), scopes: 'edit_issues')
    assert_response :forbidden
    assert_includes response.headers['WWW-Authenticate'], 'scope="edit_issues set_notes_private"'
    assert_not Journal.exists?(notes: 'Private update')
  end

  def test_search_combines_native_filters_with_existing_arguments
    user = User.find(2)
    arguments = {
      'project' => 'ecookbook', 'status' => 'open', 'sort' => 'id',
      'filters' => { 'author_id' => { 'operator' => '=', 'values' => ['2'] } }
    }
    post_mcp rpc('tools/call', { 'name' => 'search_issues', 'arguments' => arguments }), api_key_headers(user)
    assert_response :success
    assert_not json_body['result']['isError']
    expected = Issue.visible(user).open.where(project_id: 1, author_id: 2).order(:id).pluck(:id)
    assert_equal expected, json_body['result']['structuredContent']['issues'].pluck('id')
  end

  private

  def initialize_params(version)
    {
      'protocolVersion' => version,
      'capabilities' => {},
      'clientInfo' => { 'name' => 'controller-test', 'version' => '1.0.0' }
    }
  end
end
