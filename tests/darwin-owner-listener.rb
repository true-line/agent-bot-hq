# Exercise the Darwin kernel's bound/peer names, including a renamed socket,
# without a service account or a system launchd job.
require 'tmpdir'
require_relative '../helpers/darwin-owner'

Dir.mktmpdir('hq-listener-', '/private/tmp') do |dir|
  name = File.join(dir, 'original.sock')
  path = File.join(dir, 'published.sock')
  other = File.join(dir, 'different.sock')
  Socket.open(:UNIX, :STREAM) do |listener|
    listener.bind(Socket.sockaddr_un(name))
    listener.listen(Socket::SOMAXCONN)
    File.rename(name, path)
    Socket.unix_server_socket(other) do |unrelated|
      copy = listener.dup
      begin
        raise 'inherited duplicate refused' unless duplicate_socket?(listener, copy)
        raise 'different listener matched duplicate' if duplicate_socket?(listener, unrelated)
      ensure
        copy.close
      end
      expected = listener.local_address.unix_path
      raise 'renamed listener lost its original bound address' unless expected == name
      raise 'published path did not reach the listener' unless published_peer?(path, expected)
      raise 'a different socket matched' if published_peer?(other, expected)
      raise 'unreachable public path matched' if published_peer?(name, expected)
      raise 'ordinary bound address accepted as a launchd address' if launchd_address?(listener, expected)
      # Each probe closes without data. The next waiting client stays queued.
      listener.accept.first.close
      unrelated.accept.first.close
      Addrinfo.unix(path).connect do |client|
        client.write('ready')
        connection, = listener.accept
        begin
          raise 'the waiting client was consumed' unless connection.read(5) == 'ready'
          raise 'connected fd accepted as listener' if listener?(connection)
        ensure
          connection.close
        end
      end

      # A full listener queue must refuse or time out before the parent helper's
      # 2s budget. None of the pending streams should need an acceptor to finish.
      listener.listen(1)
      clients = []
      begin
        16.times do
          peer = Socket.new(:UNIX, :STREAM)
          clients << peer
          break unless peer.connect_nonblock(Socket.sockaddr_un(path), exception: false) == 0
        rescue Errno::ECONNREFUSED, Errno::EAGAIN
          break
        end
        start = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        raise 'full listener queue accepted a probe' if published_peer?(path, expected)
        raise 'full listener queue stalled' if Process.clock_gettime(Process::CLOCK_MONOTONIC) - start >= 1.5
      ensure
        clients.each(&:close)
      end
    end
  end
end
