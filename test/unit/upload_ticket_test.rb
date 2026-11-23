# frozen_string_literal: true

require File.expand_path('../test_helper', __dir__)

class RedmineMcpUploadTicketTest < ActiveSupport::TestCase
  fixtures :users

  T = RedmineMcp::UploadTicket

  def test_round_trip_keeps_user_file_and_scopes
    value = T.generate(user: User.find(2), filename: 'a.pdf', content_type: 'application/pdf',
                       oauth_scopes: %i[add_issue_notes view_issues])
    ticket = T.verify(value)

    assert_equal 2, ticket.user_id
    assert_equal 'a.pdf', ticket.filename
    assert_equal 'application/pdf', ticket.content_type
    assert_equal %i[add_issue_notes view_issues], ticket.oauth_scopes
  end

  # nil means "not OAuth, no narrowing", while [] is a token granting nothing;
  # conflating them would widen an empty OAuth grant to full permissions.
  def test_absent_and_empty_scopes_stay_distinct
    assert_nil T.verify(T.generate(user: User.find(2), filename: 'a', content_type: '', oauth_scopes: nil)).oauth_scopes
    assert_equal [], T.verify(T.generate(user: User.find(2), filename: 'a', content_type: '', oauth_scopes: [])).oauth_scopes
  end

  def test_tampered_or_garbage_tickets_are_rejected
    value = T.generate(user: User.find(2), filename: 'a', content_type: '', oauth_scopes: nil)

    assert_nil T.verify("#{value}x")
    assert_nil T.verify(value.sub(/\A./) { |c| c == 'A' ? 'B' : 'A' })
    assert_nil T.verify('garbage')
    assert_nil T.verify(nil)
  end

  def test_tickets_expire
    value = T.generate(user: User.find(2), filename: 'a', content_type: '', oauth_scopes: nil)

    travel(T::LIFETIME + 1.minute) { assert_nil T.verify(value) }
  end

  def test_a_signature_for_another_purpose_is_rejected
    value = T.verifier.generate({ 'u' => 2, 'f' => 'a', 'c' => '', 's' => nil }, purpose: 'something_else')

    assert_nil T.verify(value)
  end
end
