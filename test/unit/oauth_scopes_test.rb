# frozen_string_literal: true

require File.expand_path('../test_helper', __dir__)

class OauthScopesTest < ActiveSupport::TestCase
  def teardown
    Setting.clear_cache
  end

  def test_read_only_mode_requests_only_the_read_bootstrap
    configure('read_only' => '1')

    assert_equal RedmineMcp::OAUTH_BOOTSTRAP_SCOPES, RedmineMcp::OauthScopes.initial
  end

  def test_write_mode_adds_every_write_tool_primary_scope
    configure('read_only' => '0')

    assert_equal(
      RedmineMcp::OAUTH_BOOTSTRAP_SCOPES +
        %w[add_issues edit_issues manage_issue_relations add_issue_notes manage_versions
           edit_wiki_pages log_time edit_own_time_entries manage_subtasks set_notes_private],
      RedmineMcp::OauthScopes.initial
    )
  end

  def test_read_only_mode_includes_private_note_reading
    configure('read_only' => '1')

    assert_includes RedmineMcp::OauthScopes.initial, 'view_private_notes'
    assert_not_includes RedmineMcp::OauthScopes.initial, 'set_notes_private'
  end

  def test_write_mode_keeps_admin_and_others_time_entries_out
    configure('read_only' => '0')

    scopes = RedmineMcp::OauthScopes.initial
    %w[admin edit_time_entries].each do |scope|
      assert_not_includes scopes, scope
    end
  end

  def test_every_initial_scope_is_a_declared_tier_scope
    configure('read_only' => '0')

    RedmineMcp::OauthScopes.initial.each do |scope|
      assert RedmineMcp::ScopeChallenge::SCOPE_TIERS.key?(scope.to_sym), "#{scope} has no declared tier"
    end
  end

  private

  def configure(overrides)
    Setting.plugin_redmine_mcp = RedmineMcp::Settings::DEFAULTS.merge('enabled' => '1').merge(overrides)
    Setting.clear_cache
  end
end
