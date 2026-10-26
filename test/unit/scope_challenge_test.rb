# frozen_string_literal: true

require File.expand_path('../test_helper', __dir__)

# Pure-policy coverage for the OAuth scope correlation map. These assertions
# pin the invariants ticket 07 settled: the map is exhaustive and tier-consistent,
# correlations are one-hop and same-tier, challenges emit the hard-plus-correlated
# set in source-first order, and an undeclared or tier-crossing scope fails closed.
class RedmineMcpPluginScopeChallengeTest < ActiveSupport::TestCase
  Challenge = RedmineMcpPlugin::ScopeChallenge

  def test_every_correlation_key_and_member_is_a_declared_scope
    Challenge::CORRELATED_SCOPES.each do |source, members|
      assert Challenge::SCOPE_TIERS.key?(source), "correlation source #{source} is undeclared"
      members.each do |member|
        assert Challenge::SCOPE_TIERS.key?(member), "correlation member #{member} is undeclared"
      end
    end
  end

  # The HTTP gate builds step-up challenges through SCOPE_TIERS.fetch, so a
  # registered tool whose permission is undeclared would answer 500 instead.
  def test_every_registered_tool_permission_is_a_declared_scope
    RedmineMcpPlugin::Registry.all.filter_map(&:mcp_permission).each do |permission|
      assert Challenge::SCOPE_TIERS.key?(permission), "tool permission #{permission} is undeclared"
    end
  end

  # A challenge carries one tier, so a write tool declaring a read permission
  # (or the reverse) could never be challenged without raising.
  def test_every_registered_tool_permission_matches_the_tool_tier
    RedmineMcpPlugin::Registry.all.each do |tool|
      next if tool.mcp_permission.nil?

      assert_equal tool.write? ? :write : :read, Challenge::SCOPE_TIERS.fetch(tool.mcp_permission),
                   "#{tool.tool_name} declares a permission from the other tier"
    end
  end

  def test_no_correlation_edge_crosses_its_source_tier
    Challenge::CORRELATED_SCOPES.each do |source, members|
      source_tier = Challenge::SCOPE_TIERS.fetch(source)
      members.each do |member|
        assert_equal source_tier, Challenge::SCOPE_TIERS.fetch(member),
                     "correlation #{source} -> #{member} crosses the #{source_tier} tier"
      end
    end
  end

  def test_read_challenge_appends_same_tier_correlations_source_first
    header = Challenge.header(
      permissions: %i[view_issues],
      write: false,
      resource_metadata: 'https://example.test/.well-known/oauth-protected-resource/mcp'
    )

    assert_equal 'view_issues view_project', scope_of(header)
  end

  def test_write_challenge_bundles_only_write_tier_scopes
    header = Challenge.header(
      permissions: %i[add_issues],
      write: true,
      resource_metadata: 'https://example.test/meta'
    )

    assert_equal 'add_issues add_issue_notes', scope_of(header)
  end

  def test_private_note_and_admin_have_no_outgoing_correlation
    refute Challenge::CORRELATED_SCOPES.key?(:view_private_notes)
    refute Challenge::CORRELATED_SCOPES.key?(:set_notes_private)
    refute Challenge::CORRELATED_SCOPES.key?(:edit_wiki_pages)
    refute Challenge::CORRELATED_SCOPES.key?(:admin)
  end

  def test_union_dedupes_scopes_across_several_permissions
    header = Challenge.header(
      permissions: %i[view_issues view_wiki_pages],
      write: false,
      resource_metadata: 'https://example.test/meta'
    )

    scopes = scope_of(header).split
    assert_equal scopes.uniq, scopes, 'challenge must not repeat a scope'
    assert_includes scopes, 'view_wiki_pages'
    assert_includes scopes, 'view_project'
  end

  def test_undeclared_permission_fails_closed
    assert_raises(KeyError) do
      Challenge.header(permissions: %i[not_a_real_permission], write: false, resource_metadata: 'x')
    end
  end

  def test_read_challenge_rejects_a_write_permission
    assert_raises(ArgumentError) do
      Challenge.header(permissions: %i[add_issues], write: false, resource_metadata: 'x')
    end
  end

  private

  def scope_of(header)
    header[/scope="([^"]*)"/, 1]
  end
end
