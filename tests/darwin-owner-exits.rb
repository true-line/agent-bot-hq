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
    def fixture.published_control?(wait: 0); false; end
    raise 'public metadata refusal lost' unless fixture.send(:listener_status, listener) == 84
    def fixture.published_control?(wait: 0); true; end
    raise 'address refusal lost' unless fixture.send(:listener_status, listener) == 85
    # A failed exec has already prepared the child descriptor table. Observe
    # its real process exit, then keep the test runner's own fds intact.
    child = fork do
      $stderr.reopen(File::NULL, 'w')
      exec_hq(File.join(dir, 'private-probe-marker'), '/entry', ['run'], listener)
    end
    _, status = Process.wait2(child)
    raise 'exec refusal lost' unless status.exitstatus == 86
    Socket.unix(path) do |client|
      raise 'connected descriptor refusal lost' unless listener_status(client) == 83
    end
  end
end

# Exercise just the fixed public leaf under the same Ruby checks, without
# installing a system job or modifying any real path. Other lstat calls
# (including require/load internals) continue to use the OS.
stats = Struct.new(:kind, :uid, :mode) do
  def directory?; kind == :dir; end
  def socket?; kind == :socket; end
end
dir = stats.new(:dir, 0, 0755)
good = stats.new(:socket, 0, 0666)
File.singleton_class.prepend(Module.new do
  def lstat(path)
    sample = Thread.current[:hq_publication_lstat]
    sample && ['/private', '/private/var', CONTROL].include?(path) ? sample.call(path) : super
  end
end)

def check_samples(parent_stat, leaves, wait, expected, parent_failure: nil)
  parents = 0
  calls = 0
  Thread.current[:hq_publication_lstat] = lambda do |path|
    unless path == CONTROL
      parents += 1
      raise parent_failure if path == '/private/var' && parent_failure
      next parent_stat
    end
    sample = leaves.fetch([calls, leaves.length - 1].min)
    calls += 1
    raise sample if sample.is_a?(Class)
    sample
  end
  start = Process.clock_gettime(Process::CLOCK_MONOTONIC)
  raise 'unexpected publication result' unless published_control?(wait: wait) == expected
  [calls, parents, Process.clock_gettime(Process::CLOCK_MONOTONIC) - start]
ensure
  Thread.current[:hq_publication_lstat] = nil
end

calls, parents, = check_samples(dir, [Errno::ENOENT, good], 0.5, true)
raise 'did not recheck exact leaf and ancestry' unless calls == 2 && parents == 4
calls, _, elapsed = check_samples(dir, [Errno::ENOENT], 0.05, false)
raise 'unbounded or busy wait' unless calls.between?(2, 5) && elapsed.between?(0.045, 1)
[stats.new(:socket, 0, 0600), stats.new(:socket, 501, 0666), stats.new(:symlink, 0, 0777),
 stats.new(:file, 0, 0666), Errno::EACCES, Errno::ENOTDIR, Errno::ELOOP].each do |invalid|
  calls, = check_samples(dir, [invalid, good], 0.5, false)
  raise 'invalid leaf retried' unless calls == 1
end
calls, = check_samples(dir, [Errno::ENOENT, stats.new(:symlink, 0, 0777), good], 0.5, false)
raise 'invalid replacement retried after absence' unless calls == 2
[Errno::ENOENT, Errno::EACCES].each do |err|
  calls, parents, = check_samples(dir, [good], 0.5, false, parent_failure: err)
  raise 'invalid ancestry retried' unless calls.zero? && parents == 2
end
calls, parents, = check_samples(stats.new(:dir, 0, 0775), [good], 0.5, false)
raise 'unsafe parent accepted' unless calls.zero? && parents == 1
calls, = check_samples(dir, [Errno::ENOENT, good], 0, false)
raise 'later one-shot check retried' unless calls == 1
