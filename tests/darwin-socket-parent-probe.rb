# Disposable CI system job. Only the published endpoint varies between trials.
require_relative 'darwin-owner'
require 'timeout'

journal, owner = ARGV
File.open(journal, 'a') do |out|
  out.sync = true
  role = Etc.getpwnam('_agent-bot-hq')
  abort unless Process.euid == role.uid && Process.egid == role.gid && role.uid != 0
  out.puts 'role'
  # Call the staged helper's activated_socket once, preserving its native return
  # and count / descriptor checks. Record the direct result before exit mapping.
  factory = method(:activation)
  define_singleton_method(:activation) do
    native = factory.call
    lambda do |*arguments|
      result = native.call(*arguments)
      out.puts "native=#{result}"
      result
    end
  end
  listener = activated_socket
  abort unless listener.local_address.unix? && listener.getsockopt(Socket::SOL_SOCKET, Socket::SO_TYPE).int == Socket::SOCK_STREAM
  out.puts 'descriptor'
  Timeout.timeout(12) do
    peer, = listener.accept
    abort unless peer.getpeereid.first == Integer(owner, 10)
    nonce = peer.read(32)
    abort unless nonce && nonce.bytesize == 32
    peer.write(nonce)
    peer.close
  end
end
