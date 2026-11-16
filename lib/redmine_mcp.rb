# frozen_string_literal: true

# Defines plugin-wide constants. Zeitwerk loads the remaining files, so each
# must define the constant implied by its path; do not add manual requires here.
module RedmineMcp
  VERSION = '0.1.0'

  # Transport revisions accepted by the controller, newest first. Older
  # revisions remain for compatibility with shipped clients.
  SUPPORTED_PROTOCOL_VERSIONS = %w[2026-07-28 2025-11-25 2025-06-18].freeze

  # Read scopes every initial MCP handshake requests. The two read satellites
  # (watchers, time entries) are included as a deliberate simplicity trade-off so
  # common reads need no step-up; narrow custom tokens still rely on conditional
  # step-up. `view_private_notes` is included because it filters journals rather
  # than gating an operation, so no challenge ever asks for it and an initial
  # grant is its only path. OauthScopes.initial adds write scopes when write
  # tools are enabled. Authorization-server metadata advertises the full provider
  # scope set, not this subset.
  OAUTH_BOOTSTRAP_SCOPES = %w[
    view_issues
    view_project
    view_wiki_pages
    view_issue_watchers
    view_time_entries
    view_private_notes
  ].freeze
end
