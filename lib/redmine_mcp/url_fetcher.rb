# frozen_string_literal: true

require 'ipaddr'
require 'net/http'
require 'tempfile'

module RedmineMcp
  # Downloads a URL on the Redmine server for upload_attachment_from_url. That
  # makes the server an HTTP client acting on caller-supplied input (an SSRF
  # surface), so the policy here is deliberately narrow: https only, an
  # optional host allowlist, internal addresses refused unless an administrator
  # allows them, the connection pinned to the address that was vetted, every
  # redirect hop vetted again, and the body streamed under a size and time cap.
  #
  # Messages never include the URL, which often embeds a secret. Connection
  # failures share one message so the tool cannot be used to scan ports.
  class UrlFetcher
    MAX_REDIRECTS = 3
    OPEN_TIMEOUT = 10
    READ_TIMEOUT = 30
    TOTAL_TIMEOUT = 120
    USER_AGENT = "redmine_mcp/#{RedmineMcp::VERSION}"
    DOWNLOAD_FAILED = 'Could not download the file'

    # Everything that is not publicly routable. IPv4-mapped and NAT64 IPv6
    # addresses are checked by their embedded IPv4 address instead; 6to4 and
    # Teredo can also embed one and are refused outright.
    BLOCKED_RANGES = %w[
      0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12
      192.0.0.0/24 192.0.2.0/24 192.168.0.0/16 198.18.0.0/15 198.51.100.0/24
      203.0.113.0/24 224.0.0.0/4 240.0.0.0/4
      ::/96 100::/64 2001::/32 2001:db8::/32 2002::/16 fc00::/7 fe80::/10 ff00::/8
    ].map { |cidr| IPAddr.new(cidr) }.freeze
    NAT64 = IPAddr.new('64:ff9b::/96')

    Download = Struct.new(:io, :filename, :content_type, :size, keyword_init: true)

    class Redirect < StandardError
      attr_reader :target

      def initialize(target)
        super('redirect')
        @target = target
      end
    end
    private_constant :Redirect

    def self.fetch(url, max_bytes:)
      new(max_bytes: max_bytes, allowed_hosts: Settings.url_upload_allowed_hosts,
          allow_private: Settings.url_upload_allow_private?).fetch(url)
    end

    def self.internal_address?(ip)
      ip = embedded_ipv4(ip) || ip
      BLOCKED_RANGES.any? { |range| range.family == ip.family && range.include?(ip) }
    end

    def self.embedded_ipv4(ip)
      return unless ip.ipv6?
      return ip.native if ip.ipv4_mapped?

      IPAddr.new(ip.to_i & 0xffff_ffff, Socket::AF_INET) if NAT64.include?(ip)
    end

    # +cert_store+ replaces the system trust store; tests use it to trust a
    # local server's certificate. Verification itself is never relaxed.
    def initialize(max_bytes:, allowed_hosts: [], allow_private: false, cert_store: nil)
      @max_bytes = max_bytes
      @allowed_hosts = allowed_hosts.map { |host| host.downcase.chomp('.') }
      @allow_private = allow_private
      @cert_store = cert_store
    end

    # Returns a Download whose io is an open Tempfile at position 0; the caller
    # closes and unlinks it.
    def fetch(url)
      @deadline = monotonic + TOTAL_TIMEOUT
      uri = parse(url)
      (MAX_REDIRECTS + 1).times do
        return get(uri, vet!(uri))
      rescue Redirect => e
        uri = e.target
      end
      raise ToolError, "The URL redirected more than #{MAX_REDIRECTS} times"
    end

    def host_allowed?(host)
      return true if @allowed_hosts.empty?

      host = host.downcase.chomp('.')
      @allowed_hosts.any? do |pattern|
        pattern.start_with?('*.') ? host.end_with?(pattern[1..]) : host == pattern
      end
    end

    private

    def parse(url)
      uri = URI.parse(url.to_s.strip)
      raise ToolError, 'Not a valid URL' if uri.host.blank?

      uri
    rescue URI::InvalidURIError
      raise ToolError, 'Not a valid URL'
    end

    # Returns the address to connect to. All resolved addresses are checked, not
    # only the one used, so a host cannot mix a public and an internal record.
    def vet!(uri)
      raise ToolError, 'Only https URLs can be downloaded' unless uri.is_a?(URI::HTTPS)
      raise ToolError, 'URLs with embedded credentials are not supported' if uri.userinfo.present?

      host = uri.hostname
      raise ToolError, "Downloads from #{host} are not allowed" unless host_allowed?(host)

      addresses = resolve(host)
      if !@allow_private && addresses.any? { |address| self.class.internal_address?(address) }
        raise ToolError, "#{host} resolves to an internal address, which is not allowed"
      end

      addresses.first
    end

    def resolve(host)
      addresses = Addrinfo.getaddrinfo(host, nil, nil, :STREAM, nil, 0, timeout: OPEN_TIMEOUT)
                          .map { |info| IPAddr.new(info.ip_address) }.uniq
      raise ToolError, DOWNLOAD_FAILED if addresses.empty?

      addresses
    rescue SocketError, IPAddr::Error, Timeout::Error, SystemCallError
      raise ToolError, DOWNLOAD_FAILED
    end

    # The connection goes to the vetted address while TLS still verifies the
    # URL's host name, so a DNS answer that changes after the check cannot
    # redirect it. Proxy environment variables are ignored on purpose: a proxy
    # would resolve the host itself and bypass that pinning.
    def get(uri, address)
      http = Net::HTTP.new(uri.host, uri.port, nil)
      http.ipaddr = address.to_s
      http.use_ssl = true
      http.verify_mode = OpenSSL::SSL::VERIFY_PEER
      http.cert_store = @cert_store if @cert_store
      http.open_timeout = OPEN_TIMEOUT
      http.ssl_timeout = OPEN_TIMEOUT
      http.read_timeout = READ_TIMEOUT
      http.write_timeout = READ_TIMEOUT

      request = Net::HTTP::Get.new(uri.request_uri, 'User-Agent' => USER_AGENT, 'Accept' => '*/*')
      http.start do |connection|
        # Every non-success branch raises out of the block: Net::HTTP reads
        # whatever body is left once the block returns, without any size cap.
        connection.request(request) do |response|
          raise Redirect, redirect_target(uri, response) if response.is_a?(Net::HTTPRedirection)
          raise ToolError, "The URL answered HTTP #{response.code}" unless response.is_a?(Net::HTTPSuccess)

          return download(uri, response)
        end
      end
      raise ToolError, DOWNLOAD_FAILED
    rescue Redirect, ToolError
      raise
    rescue StandardError
      raise ToolError, DOWNLOAD_FAILED
    end

    def redirect_target(uri, response)
      location = response['Location']
      raise ToolError, DOWNLOAD_FAILED if location.blank?

      uri.merge(location)
    rescue URI::Error
      raise ToolError, DOWNLOAD_FAILED
    end

    def download(uri, response)
      raise ToolError, too_large if response['Content-Length'].to_i > @max_bytes

      file = Tempfile.new('redmine_mcp_url_upload', binmode: true)
      size = 0
      response.read_body do |chunk|
        size += chunk.bytesize
        raise ToolError, too_large if size > @max_bytes
        raise ToolError, DOWNLOAD_FAILED if monotonic > @deadline

        file.write(chunk)
      end
      file.flush
      file.rewind
      Download.new(io: file, filename: filename_for(uri, response),
                   content_type: media_type(response), size: size)
    rescue StandardError
      file&.close!
      raise
    end

    def too_large
      "The file is larger than the #{@max_bytes / 1.kilobyte} KB attachment limit"
    end

    def filename_for(uri, response)
      disposition = response['Content-Disposition'].to_s
      name = if (encoded = disposition[/filename\*\s*=\s*utf-8''([^;\s]+)/i, 1])
               URI.decode_uri_component(encoded)
             else
               disposition[/filename\s*=\s*"([^"]*)"/i, 1] || disposition[/filename\s*=\s*([^;\s]+)/i, 1]
             end
      name = File.basename(URI.decode_uri_component(uri.path.to_s)) if name.blank?
      name = name.to_s.dup.force_encoding(Encoding::UTF_8).scrub('')
      name.presence && name != '/' ? name : 'download'
    end

    def media_type(response)
      type = response['Content-Type'].to_s.split(';').first.to_s.strip.downcase
      type.match?(%r{\A[\w.+-]+/[\w.+-]+\z}) ? type : nil
    end

    def monotonic
      Process.clock_gettime(Process::CLOCK_MONOTONIC)
    end
  end
end
