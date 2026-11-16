# frozen_string_literal: true

module RedmineMcp
  # The scopes advertised for a client's initial authorization, through the
  # protected-resource metadata and the unauthenticated /mcp challenge.
  #
  # With read-only mode on this is the read bootstrap alone. With writes
  # enabled it also carries the primary permission of every registered write
  # tool, because Claude does not accumulate step-up grants: each step-up
  # re-registers with only the advertised scopes plus the one challenged scope,
  # and a reconnect falls back to the advertised scopes, so a write scope that
  # is reachable only through step-up never survives. Advertising them up front
  # is safe because effective authority stays the intersection of role
  # permissions and token scopes, and the user consents to the list.
  #
  # `admin` and `edit_time_entries` stay out and remain step-up only: the user
  # is not meant to hand administrator authority to a client by default, and
  # the time entry tools touch only the caller's own entries, which
  # `edit_own_time_entries` already covers.
  module OauthScopes
    # Argument-dependent write permissions that ride along with the write tools'
    # primary scopes: `manage_subtasks` gates parent_issue_id on create_issue and
    # update_issue, `set_notes_private` gates private notes on add_issue_note and
    # update_issue.
    ADDITIONAL_WRITE_SCOPES = %w[manage_subtasks set_notes_private].freeze

    module_function

    def initial
      return OAUTH_BOOTSTRAP_SCOPES if Settings.read_only?

      (OAUTH_BOOTSTRAP_SCOPES + write_scopes).uniq
    end

    def write_scopes
      primary = Registry.all.select(&:write?).filter_map(&:mcp_permission).map(&:to_s)
      (primary + ADDITIONAL_WRITE_SCOPES).uniq
    end
  end
end
