# frozen_string_literal: true

module RedmineMcpPlugin
  module Tools
    class ListTimeEntries < Base
      include TimeEntryHelpers

      tool_name 'list_time_entries'
      title 'List time entries'
      description 'List spent time visible to the authenticated user. All filters are optional and ' \
                  'combined with AND. Returns the latest spent_on first, with total_hours for the ' \
                  'whole filtered set.'
      permission :view_time_entries
      input_schema(
        'type' => 'object',
        'properties' => {
          'project' => { 'type' => %w[string integer],
                         'description' => 'Restrict to one project (identifier or numeric id).' },
          'issue_id' => { 'type' => 'integer',
                          'description' => 'Restrict to one issue. Requires view_issues.' },
          'user' => { 'type' => 'string', 'description' => 'Login of the user who spent the time, or "me".' },
          'from' => { 'type' => 'string', 'description' => 'Earliest spent_on (ISO-8601 date), inclusive.' },
          'to' => { 'type' => 'string', 'description' => 'Latest spent_on (ISO-8601 date), inclusive.' },
          'offset' => { 'type' => 'integer', 'minimum' => 0,
                        'description' => 'Rows to skip, for paging past the server cap. Defaults to 0.' },
          'limit' => { 'type' => 'integer', 'minimum' => 1, 'description' => 'Maximum entries to return.' }
        },
        'additionalProperties' => false
      )

      def self.required_permissions(arguments = {})
        permissions = super
        arguments['issue_id'].present? ? permissions + %i[view_issues] : permissions
      end

      private

      def perform(arguments)
        scope = TimeEntry.visible(user).includes(:project, :issue, :user, :activity)

        if (identifier = arguments['project'].presence)
          project = fetch_project(identifier)
          # .visible filters by role, not by OAuth scope.
          authorize!(:view_time_entries, project)
          scope = scope.where(project_id: project.id)
        end

        scope = scope.where(issue_id: fetch_readable_issue(arguments['issue_id']).id) if arguments['issue_id'].present?

        if (login = arguments['user'].presence)
          # A subquery rather than a lookup: unknown and invisible logins both
          # give an empty list, so the filter does not confirm accounts.
          scope = scope.where(user_id: login.to_s == 'me' ? user.id : User.where(login: login.to_s).select(:id))
        end

        scope = scope.where(time_entries: { spent_on: parse_date(arguments, 'from').. }) if arguments['from'].present?
        scope = scope.where(time_entries: { spent_on: ..parse_date(arguments, 'to') }) if arguments['to'].present?

        limit  = limit_for(arguments)
        offset = offset_for(arguments)
        rows   = scope.reorder(spent_on: :desc, id: :desc).offset(offset).limit(limit)
                      .map { |time_entry| summarise_time_entry(time_entry) }
        paged(total: scope.count, offset: offset, key: :time_entries, rows: rows)
          .merge(total_hours: scope.sum(:hours).to_f.round(2))
      end
    end
  end
end
