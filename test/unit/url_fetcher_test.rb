# frozen_string_literal: true

require File.expand_path('../test_helper', __dir__)

# Covers the server-side download policy behind upload_attachment_from_url:
# address classification, the host allowlist, refusals that must happen before
# any connection, and -- against a local TLS server whose certificate is the
# only trusted one -- redirects, size caps, and file name detection.
class RedmineMcpUrlFetcherTest < ActiveSupport::TestCase
  F = RedmineMcp::UrlFetcher

  def teardown
    @server&.close
    @thread&.kill
  end

  def test_internal_addresses_are_recognized
    %w[127.0.0.1 10.1.2.3 172.16.5.4 192.168.1.1 169.254.169.254 100.64.0.1 0.0.0.0 224.0.0.1
       ::1 :: fd00::1 fe80::1 ::ffff:10.0.0.1 ::ffff:127.0.0.1 64:ff9b::a00:1 2002:a00:1::1].each do |ip|
      assert F.internal_address?(IPAddr.new(ip)), "#{ip} must count as internal"
    end
    %w[8.8.8.8 1.1.1.1 2606:4700:4700::1111 ::ffff:8.8.8.8 64:ff9b::808:808].each do |ip|
      assert_not F.internal_address?(IPAddr.new(ip)), "#{ip} must count as public"
    end
  end

  def test_empty_allowlist_admits_any_host
    assert F.new(max_bytes: 1).host_allowed?('anything.example.org')
  end

  def test_allowlist_matches_exact_hosts_and_wildcard_subdomains
    fetcher = F.new(max_bytes: 1, allowed_hosts: ['files.example.com', '*.cdn.example.net'])

    assert fetcher.host_allowed?('files.example.com')
    assert fetcher.host_allowed?('FILES.example.com.')
    assert fetcher.host_allowed?('a.cdn.example.net')
    assert_not fetcher.host_allowed?('cdn.example.net')
    assert_not fetcher.host_allowed?('evilfiles.example.com')
    assert_not fetcher.host_allowed?('files.example.com.evil.test')
  end

  def test_only_https_is_fetched
    assert_refused 'Only https URLs can be downloaded', F.new(max_bytes: 10), 'http://example.com/file'
  end

  def test_embedded_credentials_are_refused
    assert_refused 'URLs with embedded credentials are not supported', F.new(max_bytes: 10),
                   'https://user:secret@example.com/file'
  end

  def test_invalid_urls_are_refused
    assert_refused 'Not a valid URL', F.new(max_bytes: 10), 'not a url'
    assert_refused 'Not a valid URL', F.new(max_bytes: 10), 'https:///path'
  end

  def test_host_outside_the_allowlist_is_refused_before_resolution
    fetcher = F.new(max_bytes: 10, allowed_hosts: ['files.example.com'])
    assert_refused 'Downloads from other.invalid are not allowed', fetcher, 'https://other.invalid/file'
  end

  def test_internal_addresses_are_refused_by_default
    fetcher = F.new(max_bytes: 10)
    assert_refused '127.0.0.1 resolves to an internal address, which is not allowed', fetcher, 'https://127.0.0.1/'
    assert_refused 'localhost resolves to an internal address, which is not allowed', fetcher, 'https://localhost/'
    assert_refused '169.254.169.254 resolves to an internal address, which is not allowed', fetcher,
                   'https://169.254.169.254/latest/meta-data/'
  end

  def test_connection_failures_share_one_message
    port = closed_port
    assert_refused F::DOWNLOAD_FAILED, F.new(max_bytes: 10, allow_private: true), "https://127.0.0.1:#{port}/"
  end

  def test_downloads_a_file_with_its_reported_name_and_type
    download = local_fetcher.fetch("#{base}/file")

    assert_equal 'hello world', download.io.read
    assert_equal 'report.txt', download.filename
    assert_equal 'text/plain', download.content_type
    assert_equal 11, download.size
  ensure
    download&.io&.close!
  end

  def test_name_falls_back_to_the_last_path_segment
    download = local_fetcher.fetch("#{base}/plain/notes%20v2.md")

    assert_equal 'notes v2.md', download.filename
  ensure
    download&.io&.close!
  end

  def test_follows_a_redirect_on_an_allowed_host
    download = local_fetcher.fetch("#{base}/redirect")

    assert_equal 'hello world', download.io.read
  ensure
    download&.io&.close!
  end

  def test_each_redirect_hop_is_checked_against_the_allowlist
    fetcher = local_fetcher(allowed_hosts: ['127.0.0.1'])
    assert_refused 'Downloads from localhost are not allowed', fetcher, "#{base}/redirect-away"
  end

  def test_redirect_to_an_internal_address_is_refused_when_private_addresses_are_off
    # The first hop is a public-looking name in the allowlist that only this
    # test can resolve; the redirect then lands on an internal address.
    fetcher = local_fetcher(allow_private: false)
    fetcher.define_singleton_method(:vet!) do |uri|
      next IPAddr.new('127.0.0.1') if uri.path == '/redirect'

      super(uri)
    end
    assert_refused '127.0.0.1 resolves to an internal address, which is not allowed', fetcher, "#{base}/redirect"
  end

  def test_redirect_loops_stop
    assert_refused "The URL redirected more than #{F::MAX_REDIRECTS} times", local_fetcher, "#{base}/loop"
  end

  def test_declared_oversize_body_is_refused_before_reading
    assert_refused 'The file is larger than the 1 KB attachment limit', local_fetcher, "#{base}/big-declared"
  end

  def test_undeclared_oversize_body_is_cut_off_while_streaming
    assert_refused 'The file is larger than the 1 KB attachment limit', local_fetcher, "#{base}/big-streamed"
  end

  def test_error_status_is_reported
    assert_refused 'The URL answered HTTP 404', local_fetcher, "#{base}/missing"
  end

  def test_an_untrusted_certificate_fails
    start_server
    fetcher = F.new(max_bytes: 1.kilobyte, allow_private: true)
    assert_refused F::DOWNLOAD_FAILED, fetcher, "#{base}/file"
  end

  private

  def assert_refused(message, fetcher, url)
    error = assert_raises(RedmineMcp::ToolError) { fetcher.fetch(url) }
    assert_equal message, error.message
  end

  def local_fetcher(allowed_hosts: [], allow_private: true)
    start_server
    store = OpenSSL::X509::Store.new
    store.add_cert(self.class.tls_identity.last)
    F.new(max_bytes: 1.kilobyte, allowed_hosts: allowed_hosts, allow_private: allow_private, cert_store: store)
  end

  def base
    "https://127.0.0.1:#{@port}"
  end

  def closed_port
    server = TCPServer.new('127.0.0.1', 0)
    server.addr[1]
  ensure
    server&.close
  end

  def start_server
    return if @server

    key, cert = self.class.tls_identity
    context = OpenSSL::SSL::SSLContext.new
    context.key = key
    context.cert = cert
    tcp = TCPServer.new('127.0.0.1', 0)
    @port = tcp.addr[1]
    @server = OpenSSL::SSL::SSLServer.new(tcp, context)
    @thread = Thread.new do
      loop do
        socket = @server.accept
        respond(socket)
      rescue OpenSSL::SSL::SSLError, IOError, SystemCallError
        next
      ensure
        socket&.close
      end
    end
  end

  def respond(socket)
    path = socket.gets.to_s.split[1].to_s
    while (line = socket.gets) && line != "\r\n"; end

    case path
    when '/file'
      reply(socket, 200, 'hello world',
            'Content-Type' => 'text/plain; charset=utf-8',
            'Content-Disposition' => 'attachment; filename="report.txt"')
    when %r{\A/plain/}
      reply(socket, 200, '# notes', 'Content-Type' => 'text/markdown')
    when '/redirect' then reply(socket, 302, '', 'Location' => '/file')
    when '/redirect-away' then reply(socket, 302, '', 'Location' => "https://localhost:#{@port}/file")
    when '/loop' then reply(socket, 302, '', 'Location' => '/loop')
    when '/big-declared' then reply(socket, 200, 'x' * 10, 'Content-Length' => '5000')
    when '/big-streamed'
      socket.write("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n")
      socket.write('x' * 5000)
    else reply(socket, 404, 'missing')
    end
  end

  def reply(socket, status, body, headers = {})
    headers = { 'Content-Length' => body.bytesize.to_s, 'Connection' => 'close' }.merge(headers)
    socket.write("HTTP/1.1 #{status} X\r\n#{headers.map { |k, v| "#{k}: #{v}\r\n" }.join}\r\n#{body}")
  end

  def self.tls_identity
    @tls_identity ||= begin
      key = OpenSSL::PKey::RSA.new(2048)
      cert = OpenSSL::X509::Certificate.new
      cert.version = 2
      cert.serial = 1
      cert.subject = cert.issuer = OpenSSL::X509::Name.parse('/CN=127.0.0.1')
      cert.public_key = key.public_key
      cert.not_before = Time.now - 60
      cert.not_after = Time.now + 3600
      extensions = OpenSSL::X509::ExtensionFactory.new(cert, cert)
      cert.add_extension(extensions.create_extension('basicConstraints', 'CA:TRUE', true))
      cert.add_extension(extensions.create_extension('subjectAltName', 'IP:127.0.0.1', false))
      cert.sign(key, OpenSSL::Digest.new('SHA256'))
      [key, cert]
    end
  end
end
