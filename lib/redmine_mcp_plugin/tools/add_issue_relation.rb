# frozen_string_literal: true

module RedmineMcpPlugin
  module Tools
    class AddIssueRelation < Base
      # IssueRelation::TYPES spelled out: the schema is built when this class
      # loads, and referencing a core model constant would tie eager loading of
      # the plugin to core's load order.
      RELATION_TYPES = %w[relates duplicates duplicated blocks blocked precedes follows
                          copied_to copied_from].freeze

      tool_name 'add_issue_relation'
      title 'Add issue relation'
      description 'Link two visible issues. The type reads from issue_id: "blocks" means issue_id blocks ' \
                  'issue_to_id.'
      permission :manage_issue_relations
      write true
      input_schema(
        'type' => 'object',
        'properties' => {
          'issue_id' => { 'type' => 'integer', 'description' => 'Issue the relation is added to.' },
          'issue_to_id' => { 'type' => 'integer', 'description' => 'The other issue.' },
          'relation_type' => { 'type' => 'string', 'enum' => RELATION_TYPES, 'description' => 'Defaults to relates.' },
          'delay' => { 'type' => 'integer', 'minimum' => 0,
                       'description' => 'Delay in days. Only meaningful for precedes and follows.' }
        },
        'required' => %w[issue_id issue_to_id],
        'additionalProperties' => false
      )

      private

      def perform(arguments)
        issue = fetch_visible_issue(arguments['issue_id'])
        other = fetch_visible_issue(arguments['issue_to_id'])
        # The source project only, as core's IssueRelationsController does.
        authorize!(:manage_issue_relations, issue.project)

        relation = IssueRelation.new(issue_from: issue, issue_to: other,
                                     relation_type: arguments['relation_type'].presence || 'relates')
        relation.delay = arguments['delay'] if arguments.key?('delay')
        # Writes the relation into both issues' history, as the UI does.
        relation.init_journals(user)
        begin
          saved = relation.save
        rescue ActiveRecord::RecordNotUnique
          # Core swaps reverse types (blocked -> blocks) in before_save, after
          # the uniqueness validation, so an existing link asked for from the
          # other side reaches the unique index. Core rescues it the same way.
          raise ToolError, 'These issues are already related'
        end
        raise ToolError, "Could not add relation: #{relation.errors.full_messages.join('; ')}" unless saved

        # Reverse types are stored in canonical form with the issues swapped, so
        # this reports what was stored, not what was asked.
        { id: relation.id, issue_from_id: relation.issue_from_id, issue_to_id: relation.issue_to_id,
          relation_type: relation.relation_type, delay: relation.delay }
      end

      def fetch_visible_issue(id)
        issue = Issue.visible(user).find_by(id: id.to_i)
        raise ToolError, "No visible issue with id #{id.inspect}" if issue.nil?

        issue
      end
    end
  end
end
