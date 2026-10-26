# frozen_string_literal: true

module RedmineMcpPlugin
  module Tools
    class UpdateIssue < Base
      include IssueAttributes

      tool_name 'update_issue'
      title 'Update issue'
      description 'Update fields of a visible issue by id, optionally with a note. Only the fields given ' \
                  'are changed. A change the role or workflow does not allow is refused, not ignored.'
      permission :edit_issues
      write true
      input_schema(
        'type' => 'object',
        'properties' => {
          'id' => { 'type' => 'integer', 'description' => 'Issue id.' },
          'subject' => { 'type' => 'string', 'description' => 'New issue subject.' },
          'description' => { 'type' => 'string', 'description' => 'New issue description.' },
          'tracker' => { 'type' => 'string', 'description' => 'Tracker name.' },
          'priority' => { 'type' => 'string', 'description' => 'Priority name.' },
          'status' => { 'type' => 'string',
                        'description' => 'Target status name. Must be allowed by the workflow; see list_statuses.' },
          'done_ratio' => { 'type' => 'integer', 'minimum' => 0, 'maximum' => 100,
                            'description' => 'Completion percentage.' },
          'assigned_to' => { 'type' => 'string',
                             'description' => 'Login, full name or group name of the assignee, or "none" to ' \
                                              'unassign.' },
          'category' => { 'type' => 'string', 'description' => 'Issue category name, or "none" to clear.' },
          'fixed_version' => { 'type' => 'string',
                               'description' => 'Target version name, or "none" to clear. Must be open.' },
          'parent_issue_id' => { 'type' => %w[integer string],
                                 'description' => 'Parent issue id, or "none" to make it a top-level issue. ' \
                                                  'Requires manage_subtasks.' },
          'notes' => { 'type' => 'string',
                       'description' => 'Comment to add with the update. Requires add_issue_notes.' },
          'private' => { 'type' => 'boolean',
                         'description' => 'Mark the note private. Requires notes and set_notes_private.' }
        },
        'required' => %w[id],
        'additionalProperties' => false
      )

      def self.required_permissions(arguments = {})
        permissions = super
        permissions += %i[add_issue_notes] if arguments.key?('notes')
        permissions += %i[set_notes_private] if arguments['private'] == true
        permissions += %i[manage_subtasks] if arguments.key?('parent_issue_id')
        permissions
      end

      private

      def perform(arguments)
        issue = Issue.visible(user).find_by(id: arguments['id'].to_i)
        raise ToolError, "No visible issue with id #{arguments['id'].inspect}" if issue.nil?

        # authorize! applies OAuth scopes; attributes_editable? applies
        # per-tracker role permissions, which allowed_to? does not see.
        authorize!(:edit_issues, issue.project)
        raise ToolError, 'You do not have permission to do that' unless issue.attributes_editable?(user)

        attributes = attributes_for(issue, arguments)
        notes = notes_for(issue, arguments)
        raise ToolError, 'Nothing to update' if attributes.empty? && notes.nil?

        # The journal must start before any attribute changes, as in
        # IssuesController, or the changes are saved without history.
        issue.init_journal(user, notes.to_s)
        issue.private_notes = true if notes && arguments['private'] == true
        unless attributes.empty?
          issue.safe_attributes = attributes
          ensure_applied!(issue, attributes)
        end
        raise ToolError, "Could not update issue: #{issue.errors.full_messages.join('; ')}" unless issue.save

        summarise(issue)
      rescue ActiveRecord::StaleObjectError
        raise ToolError, 'The issue was changed by someone else meanwhile; fetch it again and retry'
      end

      def attributes_for(issue, arguments)
        project = issue.project
        attributes = {}

        if arguments.key?('subject')
          subject = arguments['subject'].to_s.strip
          raise ToolError, 'subject must not be empty' if subject.empty?

          attributes['subject'] = subject
        end
        attributes['description'] = arguments['description'].to_s if arguments.key?('description')
        attributes['tracker_id'] = tracker_id_for(project, arguments['tracker']) if arguments.key?('tracker')
        attributes['priority_id'] = priority_id_for(arguments['priority']) if arguments.key?('priority')
        attributes['status_id'] = status_id_for(arguments['status']) if arguments.key?('status')
        attributes['done_ratio'] = arguments['done_ratio'].to_i if arguments.key?('done_ratio')
        if arguments.key?('assigned_to')
          attributes['assigned_to_id'] = assignee_id_for(issue.assignable_users, arguments['assigned_to'], project)
        end
        attributes['category_id'] = category_id_for(project, arguments['category']) if arguments.key?('category')
        if arguments.key?('fixed_version')
          attributes['fixed_version_id'] = fixed_version_id_for(issue, arguments['fixed_version'])
        end
        if arguments.key?('parent_issue_id')
          attributes['parent_issue_id'] = parent_issue_id_for(issue, arguments['parent_issue_id'])
        end
        attributes
      end

      # init_journal does not check add_issue_notes, so the tool does, both
      # with OAuth scopes (authorize!) and per tracker (notes_addable?).
      def notes_for(issue, arguments)
        unless arguments.key?('notes')
          raise ToolError, 'private applies to a note; give notes as well' if arguments['private'] == true

          return nil
        end

        notes = arguments['notes'].to_s
        raise ToolError, 'notes must not be empty' if notes.strip.empty?

        authorize!(:add_issue_notes, issue.project)
        raise ToolError, 'You do not have permission to do that' unless issue.notes_addable?(user)
        authorize!(:set_notes_private, issue.project) if arguments['private'] == true
        notes
      end

      def summarise(issue)
        {
          id: issue.id,
          subject: issue.subject,
          project_identifier: issue.project.identifier,
          status: issue.status&.name,
          tracker: issue.tracker&.name,
          priority: issue.priority&.name,
          assigned_to: identity(issue.assigned_to),
          category: issue.category&.name,
          fixed_version: issue.fixed_version&.name,
          parent_id: issue.parent_id,
          done_ratio: issue.done_ratio,
          journal_id: issue.current_journal&.id,
          updated_on: iso(issue.updated_on)
        }
      end
    end
  end
end
