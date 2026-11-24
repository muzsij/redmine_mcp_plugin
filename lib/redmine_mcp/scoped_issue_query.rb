# frozen_string_literal: true

module RedmineMcp
  # Redmine's journal and watcher query conditions omit OAuth narrowing, and its
  # spent-time filter sums invisible entries. Override those filter hooks for
  # this unsaved MCP query; changing host models globally would affect unrelated
  # Redmine requests.
  class ScopedIssueQuery < ::IssueQuery
    HISTORY_OPERATORS = %w[ev !ev cf].freeze

    def sql_for_notes_field(field, operator, values)
      condition = sql_for_field(field, operator.delete_prefix('!'), values, Journal.table_name, 'notes')
      journal_exists(visible_journals.where(condition), negate: operator.start_with?('!'))
    end

    def sql_for_updated_by_field(field, operator, values)
      condition = sql_for_field(field, '=', values, Journal.table_name, 'user_id')
      journal_exists(visible_journals.where(condition), negate: operator == '!')
    end

    def sql_for_last_updated_by_field(field, operator, values)
      latest_id = visible_journals.select("MAX(#{Journal.table_name}.id)")
      condition = sql_for_field(field, '=', values, Journal.table_name, 'user_id')
      journal_exists(Journal.where(id: latest_id).where(condition), negate: operator == '!')
    end

    def sql_for_watcher_id_field(field, operator, values)
      return super if User.current.allowed_to?(:view_issue_watchers, nil, global: true)

      # Core lets callers filter their own and their groups' watches without
      # view_issue_watchers. Other ids must not become an existence oracle.
      own_ids = [0, User.current.id] + User.current.groups.pluck(:id)
      own_values = values.select { |id| own_ids.include?(id.to_i) }
      return operator == '!' ? '1=1' : '1=0' if own_values.empty?

      super(field, operator, own_values)
    end

    def sql_for_spent_time_field(_field, operator, values)
      # Redmine 7 parses filter values as durations ("1:30", "1h30"). The
      # trailing to_f keeps the interpolated SQL numeric for unparsable input.
      first, second = values.first.to_s.to_hours.to_f, values.second.to_s.to_hours.to_f
      comparison = case operator
                   when '=', '>=', '<=' then "#{operator} #{first}"
                   when '><' then "BETWEEN #{first} AND #{second}"
                   when '*' then '> 0'
                   when '!*' then '= 0'
                   end
      return if comparison.nil?

      # Same rounding as core, so "=" compares against the displayed total
      # rather than an accumulated floating-point sum.
      hours = TimeEntry.visible(User.current)
                       .where("#{TimeEntry.table_name}.issue_id = #{Issue.table_name}.id")
                       .select("ROUND(CAST(SUM(#{TimeEntry.table_name}.hours) AS DECIMAL(30,3)), 2)")
      "COALESCE((#{hours.to_sql}), 0) #{comparison}"
    end

    # The "has been", "has never been", and "changed from" operators read
    # journal details through a role-only private-notes condition in core.
    def sql_for_field(field, operator, value, db_table, db_field, is_custom_filter = false)
      unless HISTORY_OPERATORS.include?(operator) && db_table == Issue.table_name && value.present?
        return super
      end

      values = value.map(&:to_s)
      changes = visible_journals.joins(:details).where(
        JournalDetail.table_name => { property: 'attr', prop_key: db_field, old_value: values }
      )
      sql = journal_exists(changes, negate: false)
      if operator != 'cf'
        sql += " OR #{Issue.send(:sanitize_sql_for_conditions, ["#{db_table}.#{db_field} IN (?)", values])}"
      end
      "#{operator.start_with?('!') ? 'NOT ' : ''}(#{sql})"
    end

    protected

    # Before Redmine 7, the search fetcher matches journal text through a
    # role-only private-notes condition that cannot be narrowed from here.
    # Withhold the filter when the OAuth token removes a private-notes
    # permission the roles would otherwise grant.
    def initialize_available_filters
      super
      delete_available_filter('any_searchable') if oauth_hides_private_notes?
    end

    private

    # Project.allowed_to_condition is the check the fetcher applies. It is
    # role-only before Redmine 7, which narrows it by the OAuth scope itself,
    # so there this finds nothing and the filter stays available.
    def oauth_hides_private_notes?
      user = User.current
      return false unless user.authorized_by_oauth?
      return false if user.allowed_to?(:view_private_notes, nil, global: true)

      Project.where(Project.allowed_to_condition(user, :view_private_notes)).exists?
    end

    def visible_journals
      scope = Journal.where(journalized_type: 'Issue')
                     .where("#{Journal.table_name}.journalized_id = #{Issue.table_name}.id")
                     .where(Journal.visible_notes_condition(User.current, skip_pre_condition: true))
      unless User.current.allowed_to?(:view_private_notes, nil, global: true)
        scope = scope.where("#{Journal.table_name}.private_notes = ? OR #{Journal.table_name}.user_id = ?",
                            false, User.current.id)
      end
      scope
    end

    def journal_exists(scope, negate:)
      "#{negate ? 'NOT ' : ''}EXISTS (#{scope.select('1').to_sql})"
    end
  end
end
