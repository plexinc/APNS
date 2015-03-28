module APNS
  require 'socket'
  require 'openssl'
  require 'json'

  class Application
    attr_accessor :host, :port, :ssl_context

    def initialize(sandbox=true, port=2195)
      @host = sandbox ? 'gateway.sandbox.push.apple.com' : 'gateway.push.apple.com'
      @port = port
    end

    def set_cert(pem_path, pass)
      raise "The path to your pem file is not set. (APNS.pem = /path/to/cert.pem)" unless pem_path
      raise "The path to your pem file does not exist!" unless File.exist?(pem_path)

      @ssl_context      = OpenSSL::SSL::SSLContext.new
      @ssl_context.cert = OpenSSL::X509::Certificate.new(File.read(pem_path))
      @ssl_context.key  = OpenSSL::PKey::RSA.new(File.read(pem_path), pass)
    end
  end

  @applications = {:default => Application.new}
  @default_pem = nil
  @default_pass = nil

  def self.host=(host)
    @applications[:default].host = host
  end

  def self.port=(port)
    @applications[:default].port = port
  end

  def self.pem=(pem)
    @default_pem = pem
    @applications[:default].set_cert(@default_pem, @default_pass) rescue
    pem
  end

  def self.pass=(pass)
    @default_pass = pass
    @applications[:default].set_cert(@default_pem, @default_pass) rescue
    pass
  end

  def self.add_application(app_id, pem_path, pass=nil, sandbox=false)
    app = Application.new(sandbox)
    app.set_cert(pem_path, pass)
    @applications[app_id] = app
  end

  def self.has_application?(app_id)
    @applications.include?(app_id)
  end

  def self.send_notification(device_token, message, app_id=:default)
    n = APNS::Notification.new(device_token, message)
    self.send_notifications([n], app_id)
  end

  def self.send_notifications(notifications, app_id=:default)
    sock, ssl = self.open_connection(app_id)

    packed_nofications = self.packed_nofications(notifications)

    notifications.each do |n|
      ssl.write(packed_nofications)
    end

    ssl.close
    sock.close
  end

  def self.packed_nofications(notifications)
    bytes = ''

    notifications.each do |notification|
      # Each notification frame consists of
      # 1. (e.g. protocol version) 2 (unsigned char [1 byte]) 
      # 2. size of the full frame (unsigend int [4 byte], big endian)
      pn = notification.packaged_notification
      bytes << ([2, pn.bytesize].pack('CN') + pn)
    end

    bytes
  end

  def self.feedback(app_id=:default)
    sock, ssl = self.feedback_connection(app_id)

    apns_feedback = []

    while message = ssl.read(38)
      timestamp, token_size, token = message.unpack('N1n1H*')
      apns_feedback << [Time.at(timestamp), token]
    end

    ssl.close
    sock.close

    return apns_feedback
  end

  protected

  def self.open_connection(app_id)
    application  = @applications[app_id]
    context      = application.ssl_context
    sock         = TCPSocket.new(application.host, application.port)
    ssl          = OpenSSL::SSL::SSLSocket.new(sock,context)
    ssl.connect

    return sock, ssl
  end

  def self.feedback_connection(app_id)
    application  = @applications[app_id]
    context      = application.ssl_context

    fhost = application.host.gsub('gateway','feedback')
    puts fhost

    sock         = TCPSocket.new(fhost, 2196)
    ssl          = OpenSSL::SSL::SSLSocket.new(sock,context)
    ssl.connect

    return sock, ssl
  end
end
