# frozen_string_literal: true

require File.expand_path('../test_helper', __dir__)

# Covers update_issue, add_issue_relation and the extended create_issue
# through a mounted MCP::Server. jsmith (2) is a Manager on ecookbook and
# dlopper (3) a Developer there.
class RedmineMcpPluginIssueUpdateToolsTest < ActiveSupport::TestCase
  fixtures :projects, :users, :email_addresses, :roles, :members, :member_roles,
           :issues, :issue_statuses, :trackers, :projects_trackers, :enumerations,
           :enabled_modules, :workflows, :issue_categories, :versions, :journals,
           :journal_details, :issue_relations

  def setup
    Setting.plugin_redmine_mcp_plugin = RedmineMcpPlugin::Settings::DEFAULTS.merge('read_only' => '0')
    Setting.clear_cache
    Role.find(1).add_permission!(:edit_issues, :add_issue_notes, :set_notes_private,
                                 :manage_issue_relations, :manage_subtasks, :add_issues)
  end

  def teardown
    Setting.clear_cache
    User.current = nil
  end

  def test_write_tools_are_hidden_in_read_only_mode
    Setting.plugin_redmine_mcp_plugin = RedmineMcpPlugin::Settings::DEFAULTS.merge('read_only' => '1')
    Setting.clear_cache
    names = tools_list(build_server(User.find(2))).map { |t| t[:name] }

    assert_not_includes names, 'update_issue'
    assert_not_includes names, 'add_issue_relation'
  end

  # Every role, so no other membership grants edit_issues globally.
  def test_update_issue_is_hidden_without_edit_issues
    Role.find_each { |role| role.remove_permission!(:edit_issues) }

    assert_not_includes tools_list(build_server(User.find(2))).map { |t| t[:name] }, 'update_issue'
  end

  def test_update_issue_changes_given_fields_and_records_history
    issue = Issue.find(1)

    result = call_as(User.find(2), 'update_issue',
                     'id' => 1, 'subject' => 'Renamed via MCP', 'priority' => 'High', 'notes' => 'Why')[:result]

    assert_not result[:isError], error_text(result)
    issue.reload
    assert_equal 'Renamed via MCP', issue.subject
    assert_equal 'High', issue.priority.name
    journal = issue.journals.order(:id).last
    assert_equal 'Why', journal.notes
    assert_includes journal.details.map(&:prop_key), 'subject'
  end

  def test_update_issue_without_notes_still_records_history
    call_as(User.find(2), 'update_issue', 'id' => 1, 'subject' => 'History only')

    assert_includes Issue.find(1).journals.order(:id).last.details.map(&:prop_key), 'subject'
  end

  def test_update_issue_refuses_a_status_transition_the_workflow_denies
    WorkflowTransition.where(tracker_id: Issue.find(1).tracker_id).delete_all
    before = Issue.find(1).status_id

    assert_no_difference 'Journal.count' do
      result = call_as(User.find(2), 'update_issue', 'id' => 1, 'status' => 'Closed', 'notes' => 'x')[:result]

      assert result[:isError]
      assert_match(/status_id/, error_text(result))
    end
    assert_equal before, Issue.find(1).status_id
  end

  def test_update_issue_refuses_private_without_notes
    result = call_as(User.find(2), 'update_issue', 'id' => 1, 'subject' => 'x', 'private' => true)[:result]

    assert result[:isError]
    assert_not_equal 'x', Issue.find(1).subject
  end

  def test_update_issue_notes_require_add_issue_notes
    Role.find(1).remove_permission!(:add_issue_notes)

    assert_no_difference 'Journal.count' do
      assert refused?(call_as(User.find(2), 'update_issue', 'id' => 1, 'notes' => 'sneaky'))
    end
  end

  def test_update_issue_assigns_by_full_name
    result = call_as(User.find(2), 'update_issue', 'id' => 1, 'assigned_to' => 'Dave Lopper')[:result]

    assert_not result[:isError], error_text(result)
    assert_equal 3, Issue.find(1).assigned_to_id
  end

  def test_assignee_lookup_never_matches_an_email_address
    result = call_as(User.find(2), 'update_issue', 'id' => 1, 'assigned_to' => User.find(3).mail)[:result]

    assert result[:isError]
    assert_match(/not an assignable user or group/, error_text(result))
  end

  def test_update_issue_unassigns_with_none
    Issue.find(1).update_columns(assigned_to_id: 3)

    result = call_as(User.find(2), 'update_issue', 'id' => 1, 'assigned_to' => 'none')[:result]

    assert_not result[:isError], error_text(result)
    assert_nil Issue.find(1).assigned_to_id
  end

  def test_update_issue_refuses_invisible_issue_like_a_missing_one
    invisible = Issue.where(project_id: 2).first
    Role.find(2).add_permission!(:edit_issues)
    assert_not invisible.visible?(User.find(3))

    hidden = call_as(User.find(3), 'update_issue', 'id' => invisible.id, 'subject' => 'x')[:result]
    missing = call_as(User.find(3), 'update_issue', 'id' => 999_999, 'subject' => 'x')[:result]

    assert hidden[:isError]
    assert_equal error_text(missing).sub('999999', invisible.id.to_s), error_text(hidden)
  end

  def test_add_issue_relation_links_two_visible_issues
    IssueRelation.where(issue_from_id: [1, 2], issue_to_id: [1, 2]).delete_all

    result = call_as(User.find(2), 'add_issue_relation',
                     'issue_id' => 1, 'issue_to_id' => 2, 'relation_type' => 'blocks')[:result]

    assert_not result[:isError], error_text(result)
    assert IssueRelation.exists?(issue_from_id: 1, issue_to_id: 2, relation_type: 'blocks')
  end

  def test_add_issue_relation_refuses_an_invisible_target
    invisible = Issue.where(project_id: 2).first
    Role.find(2).add_permission!(:manage_issue_relations)
    assert_not invisible.visible?(User.find(3))

    assert_no_difference 'IssueRelation.count' do
      result = call_as(User.find(3), 'add_issue_relation', 'issue_id' => 1, 'issue_to_id' => invisible.id)[:result]

      assert result[:isError]
      assert_match(/No visible issue/, error_text(result))
    end
  end

  def test_create_issue_sets_category_and_reports_it
    category = IssueCategory.where(project_id: 1).first

    result = call_as(User.find(2), 'create_issue',
                     'project' => 'ecookbook', 'subject' => 'With category', 'category' => category.name)[:result]

    assert_not result[:isError], error_text(result)
    assert_equal category.id, Issue.find(result[:structuredContent][:id]).category_id
  end

  def test_create_issue_refuses_parent_without_manage_subtasks
    Role.find(1).remove_permission!(:manage_subtasks)

    assert_no_difference 'Issue.count' do
      assert refused?(call_as(User.find(2), 'create_issue',
                              'project' => 'ecookbook', 'subject' => 'Child', 'parent_issue_id' => 1))
    end
  end

  private

  # An unmounted or backstopped tool is refused; a mounted one reports isError.
  def refused?(response)
    response[:error].present? || response.dig(:result, :isError)
  end

  def error_text(result)
    result[:content]&.first&.dig(:text)
  end

  # The controller sets User.current before the tool runs; Issue's
  # safe_attributes and journals read it, so the tests do too.
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
end
