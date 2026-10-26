# frozen_string_literal: true

module RedmineMcpPlugin
  module Tools
    class CreateIssue < Base
      include IssueAttributes

      tool_name 'create_issue'
      title 'Create issue'
      description 'Create a new issue in a project. A field the role or workflow does not allow is ' \
                  'refused, not ignored.'
      permission :add_issues
      write true
      input_schema(
        'type' => 'object',
        'properties' => {
          'project' => { 'type' => %w[string integer],
                         'description' => 'Project identifier or numeric id.' },
          'subject' => { 'type' => 'string', 'description' => 'Issue subject.' },
          'description' => { 'type' => 'string' },
          'tracker' => { 'type' => 'string', 'description' => 'Tracker name. Defaults to the project default.' },
          'priority' => { 'type' => 'string', 'description' => 'Priority name. Defaults to the Redmine default.' },
          'status' => { 'type' => 'string',
                        'description' => 'Status name. Defaults to the tracker default. Must be allowed by the ' \
                                         'workflow for new issues.' },
          'assigned_to' => { 'type' => 'string',
                             'description' => 'Login, full name or group name of the user or group to assign to.' },
          'category' => { 'type' => 'string', 'description' => 'Issue category name in the project.' },
          'fixed_version' => { 'type' => 'string', 'description' => 'Target version name. Must be open.' },
          'parent_issue_id' => { 'type' => 'integer', 'description' => 'Parent issue id. Requires manage_subtasks.' }
        },
        'required' => %w[project subject],
        'additionalProperties' => false
      )

      def self.required_permissions(arguments = {})
        permissions = super
        arguments['parent_issue_id'].present? ? permissions + %i[manage_subtasks] : permissions
      end

      private

      def perform(arguments)
        project = fetch_project(arguments['project'])
        authorize!(:add_issues, project)

        issue = Issue.new(project: project, author: user)
        attributes = { 'subject' => arguments['subject'].to_s.strip }
        attributes['description'] = arguments['description'].to_s if arguments.key?('description')
        attributes['tracker_id'] = tracker_id_for(project, arguments['tracker']) if arguments['tracker'].present?
        attributes['priority_id'] = priority_id_for(arguments['priority']) if arguments['priority'].present?
        attributes['status_id'] = status_id_for(arguments['status']) if arguments['status'].present?
        if arguments['assigned_to'].present?
          attributes['assigned_to_id'] = assignee_id_for(project.assignable_users, arguments['assigned_to'], project)
        end
        attributes['category_id'] = category_id_for(project, arguments['category']) if arguments['category'].present?
        if arguments['fixed_version'].present?
          attributes['fixed_version_id'] = fixed_version_id_for(issue, arguments['fixed_version'])
        end
        if arguments['parent_issue_id'].present?
          attributes['parent_issue_id'] = parent_issue_id_for(issue, arguments['parent_issue_id'])
        end

        issue.safe_attributes = attributes
        ensure_applied!(issue, attributes.except('subject'))
        raise ToolError, "Could not create issue: #{issue.errors.full_messages.join('; ')}" unless issue.save

        { id: issue.id, subject: issue.subject, project_identifier: project.identifier,
          status: issue.status&.name, tracker: issue.tracker&.name, assigned_to: identity(issue.assigned_to),
          category: issue.category&.name, fixed_version: issue.fixed_version&.name, parent_id: issue.parent_id,
          created_on: iso(issue.created_on) }
      end
    end
  end
end
