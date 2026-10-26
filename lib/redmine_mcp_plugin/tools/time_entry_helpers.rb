# frozen_string_literal: true

module RedmineMcpPlugin
  module Tools
    # Shared by the time entry tools so they parse arguments and render entries
    # the same way.
    module TimeEntryHelpers
      private

      # Checked before authorize! for the reason given on Base#fetch_wiki.
      def require_time_tracking!(project)
        return if project.module_enabled?(:time_tracking)

        raise ToolError, "The time tracking module is not enabled for project #{project.identifier}"
      end

      # Issue.visible honors roles but not OAuth scopes, so a token without
      # view_issues must not be able to tell a hidden issue from a missing one.
      # One message for both keeps the lookup from confirming existence.
      def fetch_readable_issue(id)
        issue = Issue.visible(user).find_by(id: id.to_i)
        raise ToolError, "No visible issue with id #{id.inspect}" unless issue_readable?(issue)

        issue
      end

      def issue_readable?(issue)
        issue.present? && issue.visible?(user) && user.allowed_to?(:view_issues, issue.project)
      end

      # Only the caller's own entries. One refusal whether the entry is missing,
      # invisible or somebody else's, so the message does not confirm that an
      # entry exists.
      def fetch_own_time_entry(id)
        time_entry = TimeEntry.visible(user).where(user_id: user.id).find_by(id: id.to_i)
        raise ToolError, "No time entry of yours with id #{id.inspect}" if time_entry.nil?

        require_time_tracking!(time_entry.project)
        # Core's rule (edit_own_time_entries on own entries, or
        # edit_time_entries); allowed_to? inside it honors OAuth scopes.
        raise ToolError, 'You do not have permission to do that' unless time_entry.editable_by?(user)

        time_entry
      end

      # Attributes for safe_attributes=, taken only from the arguments present.
      # Project, issue and user are never accepted here: moving an entry or
      # logging for someone else needs permissions these tools do not check.
      def time_entry_attributes(arguments, project)
        attributes = {}
        attributes['hours'] = arguments['hours'].to_s if arguments.key?('hours')
        attributes['comments'] = arguments['comments'].to_s if arguments.key?('comments')
        attributes['spent_on'] = parse_date(arguments, 'spent_on').to_s if arguments['spent_on'].present?

        if (activity_name = arguments['activity'].presence)
          # project.activities, not TimeEntryActivity.active: a project may
          # disable or override the shared activities.
          activity = project.activities.find_by(name: activity_name.to_s)
          if activity.nil?
            raise ToolError, "Project #{project.identifier} has no active activity named #{activity_name.inspect}"
          end

          attributes['activity_id'] = activity.id
        end

        attributes
      end

      def parse_date(arguments, key)
        Date.iso8601(arguments[key].to_s)
      rescue ArgumentError
        raise ToolError, "#{key} must be an ISO-8601 date, got #{arguments[key].inspect}"
      end

      # TimeEntry.visible does not check the entry's issue, so the issue
      # reference is withheld when the caller cannot read that issue.
      def summarise_time_entry(time_entry)
        issue = time_entry.issue
        readable = issue_readable?(issue)
        {
          id: time_entry.id,
          spent_on: time_entry.spent_on&.iso8601,
          # hours is a Rational-like value; to_json would render 3 as "3/1".
          hours: time_entry.hours&.to_f,
          project_identifier: time_entry.project&.identifier,
          issue_id: readable ? issue.id : nil,
          issue_subject: readable ? issue.subject : nil,
          user: identity(time_entry.user),
          activity: time_entry.activity&.name,
          comments: time_entry.comments,
          created_on: iso(time_entry.created_on),
          updated_on: iso(time_entry.updated_on)
        }
      end
    end
  end
end
