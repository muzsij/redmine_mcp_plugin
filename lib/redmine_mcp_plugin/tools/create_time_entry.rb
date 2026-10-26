# frozen_string_literal: true

module RedmineMcpPlugin
  module Tools
    class CreateTimeEntry < Base
      include TimeEntryHelpers

      tool_name 'create_time_entry'
      title 'Log time'
      description 'Log spent time for the authenticated user on an issue or a project.'
      permission :log_time
      write true
      input_schema(
        'type' => 'object',
        'properties' => {
          'issue_id' => { 'type' => 'integer',
                          'description' => 'Issue to log time on. Either this or project is required. ' \
                                           'Requires view_issues.' },
          'project' => { 'type' => %w[string integer],
                         'description' => 'Project identifier or numeric id, for time not tied to an issue.' },
          'hours' => { 'type' => 'number', 'minimum' => 0, 'description' => 'Hours spent, e.g. 1.5.' },
          'spent_on' => { 'type' => 'string',
                          'description' => 'ISO-8601 date the time was spent on. Defaults to today.' },
          'activity' => { 'type' => 'string',
                          'description' => 'Activity name. Defaults to the default activity. ' \
                                           'See list_enumerations.' },
          'comments' => { 'type' => 'string', 'description' => 'Short description of the work.' }
        },
        'required' => %w[hours],
        'additionalProperties' => false
      )

      def self.required_permissions(arguments = {})
        permissions = super
        arguments['issue_id'].present? ? permissions + %i[view_issues] : permissions
      end

      private

      def perform(arguments)
        issue, project = target(arguments)
        require_time_tracking!(project)
        authorize!(:log_time, project)

        # Mirrors TimelogController#create: author and user are the caller, never
        # client input. Logging for someone else needs log_time_for_other_users,
        # which this tool does not offer.
        time_entry = TimeEntry.new(project: project, issue: issue, author: user, user: user,
                                   spent_on: user.today)
        time_entry.safe_attributes = time_entry_attributes(arguments, project)
        raise ToolError, "Could not log time: #{time_entry.errors.full_messages.join('; ')}" unless time_entry.save

        summarise_time_entry(time_entry)
      end

      def target(arguments)
        if arguments['issue_id'].present?
          issue = fetch_readable_issue(arguments['issue_id'])
          if arguments['project'].present? && fetch_project(arguments['project']) != issue.project
            raise ToolError, "Issue #{issue.id} does not belong to project #{arguments['project'].inspect}"
          end

          [issue, issue.project]
        elsif arguments['project'].present?
          [nil, fetch_project(arguments['project'])]
        else
          raise ToolError, 'Either issue_id or project is required'
        end
      end
    end
  end
end
