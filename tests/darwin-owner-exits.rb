# Exercise the actual launcher boundaries with process-local fixtures.
require 'stringio'
require 'tmpdir'
require_relative '../helpers/darwin-owner'

def expect_exit(code)
  saved = $stderr
  $stderr = StringIO.new
  begin
    yield
    raise 'unexpected success'
  rescue SystemExit => e
    raise "unexpected exit #{e.status}" unless e.status == code
    raise 'private path entered stderr' if $stderr.string.include?('private-probe-marker')
  ensure
    $stderr = saved
  end
end

# This test process is outside launchd, so a real check-in must fail.
expect_exit(81) { activated_socket }

fixture = Object.new
def fixture.activation
  lambda { |_name, _list, count| count[0, Fiddle::SIZEOF_SIZE_T] = [2].pack('J'); 0 }
end
expect_exit(82) { fixture.send(:activated_socket) }

Dir.mktmpdir('hq-exits-', '/private/tmp') do |dir|
  path = File.join(dir, 'bound')
  Socket.unix_server_socket(path) do |listener|
    # Only the test receiver supplies synthetic public metadata. No production
    # entrypoint accepts an override for CONTROL, role, descriptor, or proof.
    def fixture.published_control?; false; end
    raise 'public metadata refusal lost' unless fixture.send(:listener_status, listener) == 84
    def fixture.published_control?; true; end
    raise 'address refusal lost' unless fixture.send(:listener_status, listener) == 85
    expect_exit(86) { exec_hq(File.join(dir, 'private-probe-marker'), '/entry', ['run'], listener) }
    Socket.unix(path) do |client|
      raise 'connected descriptor refusal lost' unless listener_status(client) == 83
    end
  end
end
