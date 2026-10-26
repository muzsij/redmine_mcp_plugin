# frozen_string_literal: true

require File.expand_path('../test_helper', __dir__)

# Covers the time entry tools through a mounted MCP::Server, so discovery,
# the execution backstop and the tool bodies run together. dlopper (3) is a
# Developer on ecookbook; jsmith (2) is a Manager there.
class RedmineMcpPluginTimeEntryToolsTest < ActiveSupport::TestCase
  fixtures :projects, :users, :email_addresses, :roles, :members, :member_roles,
           :issues, :issue_statuses, :trackers, :enumerations, :enabled_modules,
           :time_entries, :projects_trackers

  def setup
    Setting.plugin_redmine_mcp_plugin = RedmineMcpPlugin::Settings::DEFAULTS.merge('read_only' => '1')
    Setting.clear_cache
    Role.find(2).add_permission!(:log_time, :view_time_entries, :edit_own_time_entries)
    Role.find(2).remove_permission!(:edit_time_entries)
  end

  def teardown
    Setting.clear_cache
    User.current = nil
  end

  def test_list_enumerations_includes_shared_activities
    activities = call_as(User.find(3), 'list_enumerations')[:result][:structuredContent][:time_entry_activities]

    assert activities.present?
    assert(activities.all? { |a| a.key?(:id) && a.key?(:name) })
  end

  def test_list_time_entries_returns_visible_entries_and_total_hours
    result = call_as(User.find(3), 'list_time_entries', 'project' => 'ecookbook')[:result]

    assert_not result[:isError], error_text(result)
    payload = result[:structuredContent]
    expected = TimeEntry.visible(User.find(3)).where(project_id: 1)
    assert_equal expected.count, payload[:total_count]
    assert_in_delta expected.sum(:hours).to_f, payload[:total_hours], 0.01
  end

  def test_list_time_entries_withholds_issue_of_unreadable_issue
    issue = Issue.find(1)
    issue.update_columns(is_private: true, author_id: 1, assigned_to_id: nil)
    Role.find(2).update!(issues_visibility: 'default')
    entry = make_entry(User.find(2), issue)
    assert_not issue.visible?(User.find(3))

    rows = call_as(User.find(3), 'list_time_entries', 'project' => 'ecookbook')[:result][:structuredContent][:time_entries]
    row = rows.find { |r| r[:id] == entry.id }

    assert row, 'the entry itself stays visible under the role time entry visibility'
    assert_nil row[:issue_id]
    assert_nil row[:issue_subject]
  end

  def test_list_time_entries_issue_filter_does_not_distinguish_invisible_from_missing
    invisible = Issue.where(project_id: 2).first
    assert_not invisible.visible?(User.find(3))

    hidden = call_as(User.find(3), 'list_time_entries', 'issue_id' => invisible.id)[:result]
    missing = call_as(User.find(3), 'list_time_entries', 'issue_id' => 999_999)[:result]

    assert hidden[:isError]
    assert_equal error_text(missing).sub('999999', invisible.id.to_s), error_text(hidden)
  end

  def test_write_tools_are_hidden_in_read_only_mode
    names = tools_list(build_server(User.find(3))).map { |t| t[:name] }

    assert_includes names, 'list_time_entries'
    assert_not_includes names, 'create_time_entry'
    assert_not_includes names, 'update_time_entry'
    assert_not_includes names, 'delete_time_entry'
  end

  def test_delete_time_entry_is_advertised_as_destructive
    annotations = RedmineMcpPlugin::Tools::DeleteTimeEntry.to_h[:annotations]

    assert_not annotations[:readOnlyHint]
    assert annotations[:destructiveHint]
  end

  def test_create_time_entry_logs_time_as_the_caller_on_an_issue
    with_read_only_off do
      result = call_as(User.find(3), 'create_time_entry',
                       'issue_id' => 1, 'hours' => 1.5, 'comments' => 'MCP', 'spent_on' => '2026-01-05')[:result]

      assert_not result[:isError], error_text(result)
      entry = TimeEntry.find(result[:structuredContent][:id])
      assert_equal 3, entry.user_id
      assert_equal 3, entry.author_id
      assert_equal 1, entry.issue_id
      assert_in_delta 1.5, entry.hours, 0.001
      assert_equal Date.new(2026, 1, 5), entry.spent_on
    end
  end

  def test_create_time_entry_refuses_invisible_issue_like_a_missing_one
    invisible = Issue.where(project_id: 2).first

    with_read_only_off do
      assert_no_difference 'TimeEntry.count' do
        hidden = call_as(User.find(3), 'create_time_entry', 'issue_id' => invisible.id, 'hours' => 1)[:result]
        missing = call_as(User.find(3), 'create_time_entry', 'issue_id' => 999_999, 'hours' => 1)[:result]

        assert hidden[:isError]
        assert_equal error_text(missing).sub('999999', invisible.id.to_s), error_text(hidden)
      end
    end
  end

  def test_create_time_entry_rejects_a_mismatched_project
    with_read_only_off do
      result = call_as(User.find(2), 'create_time_entry',
                       'issue_id' => 1, 'project' => 'onlinestore', 'hours' => 1)[:result]

      assert result[:isError]
    end
  end

  def test_create_time_entry_requires_log_time_on_the_project
    Role.find(2).remove_permission!(:log_time)

    with_read_only_off do
      assert_not_includes tools_list(build_server(User.find(3))).map { |t| t[:name] }, 'create_time_entry'
      assert refused?(call_as(User.find(3), 'create_time_entry', 'project' => 'ecookbook', 'hours' => 1))
    end
  end

  def test_update_time_entry_changes_only_given_fields_of_own_entry
    entry = make_entry(User.find(3), Issue.find(1), comments: 'before')

    with_read_only_off do
      result = call_as(User.find(3), 'update_time_entry', 'id' => entry.id, 'hours' => 2)[:result]

      assert_not result[:isError], error_text(result)
    end
    entry.reload
    assert_in_delta 2.0, entry.hours, 0.001
    assert_equal 'before', entry.comments
  end

  def test_update_time_entry_refuses_someone_elses_entry_like_a_missing_one
    other = make_entry(User.find(2), Issue.find(1))

    with_read_only_off do
      foreign = call_as(User.find(3), 'update_time_entry', 'id' => other.id, 'hours' => 9)[:result]
      missing = call_as(User.find(3), 'update_time_entry', 'id' => 999_999, 'hours' => 9)[:result]

      assert foreign[:isError]
      assert_equal error_text(missing).sub('999999', other.id.to_s), error_text(foreign)
    end
    assert_not_in_delta 9.0, other.reload.hours, 0.001
  end

  def test_delete_time_entry_deletes_own_entry
    entry = make_entry(User.find(3), Issue.find(1))

    with_read_only_off do
      result = call_as(User.find(3), 'delete_time_entry', 'id' => entry.id)[:result]

      assert_not result[:isError], error_text(result)
      assert result[:structuredContent][:deleted]
    end
    assert_not TimeEntry.exists?(entry.id)
  end

  def test_delete_time_entry_requires_edit_permission
    entry = make_entry(User.find(3), Issue.find(1))
    Role.find(2).remove_permission!(:edit_own_time_entries)

    with_read_only_off do
      assert_not_includes tools_list(build_server(User.find(3))).map { |t| t[:name] }, 'delete_time_entry'
      assert refused?(call_as(User.find(3), 'delete_time_entry', 'id' => entry.id))
    end
    assert TimeEntry.exists?(entry.id)
  end

  private

  def make_entry(user, issue, comments: 'fixture')
    TimeEntry.create!(project: issue.project, issue: issue, user: user, author: user, hours: 1,
                      spent_on: Date.new(2026, 1, 2), comments: comments,
                      activity: TimeEntryActivity.default || TimeEntryActivity.active.first)
  end

  # An unmounted tool is a JSON-RPC error; a mounted one refuses in its result.
  def refused?(response)
    response[:error].present? || response.dig(:result, :isError)
  end

  def error_text(result)
    result[:content]&.first&.dig(:text)
  end

  # The controller sets User.current before the tool runs; TimeEntry's
  # safe_attributes and default activity read it, so the tests do too.
  def build_server(user)
    User.current = user
    RedmineMcpPlugin::McpServer.build(
      tools: RedmineMcpPlugin::Registry.all.select { |tool| tool.available_to?(user, oauth_scopes: nil) },
      server_context: { user: user, auth: { mode: :api_key } }
    )
  end

  def call_as(user, name, arguments = {})
    build_server(user).handle(
      { jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: name, arguments: arguments } }
    )
  end

  def tools_list(server)
    server.handle({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} })[:result][:tools]
  end

  def with_read_only_off
    Setting.plugin_redmine_mcp_plugin = RedmineMcpPlugin::Settings::DEFAULTS.merge('read_only' => '0')
    Setting.clear_cache
    yield
  ensure
    Setting.plugin_redmine_mcp_plugin = RedmineMcpPlugin::Settings::DEFAULTS.merge('read_only' => '1')
    Setting.clear_cache
  end
end
