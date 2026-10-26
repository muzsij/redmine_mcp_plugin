# frozen_string_literal: true

module RedmineMcpPlugin
  module Tools
    # Name-to-id resolution shared by create_issue and update_issue for the
    # fields a caller names rather than numbers. "none" clears an optional
    # field.
    module IssueAttributes
      private

      def none?(value)
        value.to_s.strip.casecmp('none').zero?
      end

      def tracker_id_for(project, name)
        tracker = project.trackers.find_by(name: name.to_s)
        raise ToolError, "Project #{project.identifier} has no tracker named #{name.to_s.inspect}" if tracker.nil?

        tracker.id
      end

      def priority_id_for(name)
        priority = IssuePriority.active.find_by(name: name.to_s)
        raise ToolError, "No active priority named #{name.to_s.inspect}" if priority.nil?

        priority.id
      end

      # Whether the workflow allows the transition is left to safe_attributes=
      # and reported by ensure_applied!.
      def status_id_for(name)
        status = IssueStatus.find_by(name: name.to_s)
        raise ToolError, "No issue status named #{name.to_s.inspect}" if status.nil?

        status.id
      end

      def category_id_for(project, name)
        return nil if none?(name)

        category = project.issue_categories.find_by(name: name.to_s)
        raise ToolError, "Project #{project.identifier} has no category named #{name.to_s.inspect}" if category.nil?

        category.id
      end

      # assignable_versions applies version sharing and leaves out closed and
      # locked versions, which is what the issue form offers.
      def fixed_version_id_for(issue, name)
        return nil if none?(name)

        version = issue.assignable_versions.detect { |candidate| candidate.name == name.to_s }
        if version.nil?
          raise ToolError, "No open version named #{name.to_s.inspect} is available in #{issue.project.identifier}"
        end

        version.id
      end

      # parent_issue_id is a safe attribute only with manage_subtasks, so it is
      # checked up front and reported instead of silently dropped. Core
      # validates cross-project subtask settings and cycles on save.
      def parent_issue_id_for(issue, value)
        authorize!(:manage_subtasks, issue.project)
        return nil if none?(value)

        parent = Issue.visible(user).find_by(id: value.to_s.delete_prefix('#').to_i)
        raise ToolError, "No visible issue with id #{value.inspect}" if parent.nil?

        parent.id
      end

      # Login first, then the display name (which covers groups), then
      # "First Last". Unlike Principal.detect_by_keyword this never matches an
      # email address, so the lookup cannot confirm a member's hidden address.
      def assignee_id_for(candidates, value, project)
        return nil if value.to_s.strip.empty? || none?(value)

        keyword = value.to_s.strip
        principal = candidates.detect { |p| p.is_a?(User) && keyword.casecmp(p.login.to_s).zero? } ||
                    candidates.detect { |p| keyword.casecmp(p.name.to_s).zero? } ||
                    candidates.detect do |p|
                      p.is_a?(User) && keyword.casecmp("#{p.firstname} #{p.lastname}").zero?
                    end
        raise ToolError, "#{keyword.inspect} is not an assignable user or group on #{project.identifier}" if principal.nil?

        principal.id
      end

      # safe_attributes= drops fields the user's role, the workflow (read-only
      # fields, disallowed status transitions) or derived values do not allow,
      # without an error. Every field the caller sent is compared after
      # assignment so a dropped change is refused instead of reported as done.
      def ensure_applied!(issue, attributes)
        ignored = attributes.reject { |key, value| normalize(issue.public_send(key)) == normalize(value) }.keys
        return if ignored.empty?

        raise ToolError, "Not allowed to set #{ignored.join(', ')} on this issue"
      end

      # Issue#description= rewrites line endings to CRLF.
      def normalize(value)
        value.is_a?(String) ? value.gsub(/\r\n?/, "\n") : value
      end
    end
  end
end
