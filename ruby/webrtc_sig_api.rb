require 'base64'
require 'openssl'
require 'json'
require 'zlib'

class WebrtcSigApi
  attr_accessor :sdk_app_id, :private_key, :public_key

  def initialize(sdk_app_id, private_key, public_key)
    @sdk_app_id, @private_key, @public_key = sdk_app_id, private_key, public_key
  end

  def gen_user_sig(user_id, account_type = 0, expire = 300)
    json = {
      'TLS.account_type' => account_type.to_s,
      'TLS.identifier' => user_id.to_s,
      'TLS.appid_at_3rd' => '0',
      'TLS.sdk_appid' => sdk_app_id.to_s,
      'TLS.expire_after' => expire.to_s,
      'TLS.version' => '201512300000',
      'TLS.time' => Time.now.to_i.to_s
    }
    content = gen_sign_content_for_user_sig(json)
    signature = sign(content)
    json['TLS.sig'] = Base64.strict_encode64(signature)
    if json['TLS.sig'].nil?
      raise "sig base64 error"
    end
    json_str = JSON.generate(json)
    data = Zlib::Deflate.deflate(json_str)
    return base64_encode(data)
  end

  def verify_user_sig(user_sig, user_id)
    data = base64_decode(user_sig)
    json_str = Zlib::Inflate.inflate(data)
    json = JSON.parse(json_str)
    if json['TLS.identifier'] != user_id.to_s
      raise "identifier not match, identifier: #{ json['TLS.identifier']}, user_id: #{user_id}"
    end
    if json['TLS.sdk_appid'] != sdk_app_id.to_s
      raise "sdk_appid not match, sdk_appid: #{ json['TLS.sdk_appid']}, sdk_app_id: #{sdk_app_id}"
    end
    signature = Base64.strict_decode64(json['TLS.sig'])
    if signature.nil?
      raise "userSig json decode error"
    end
    content = gen_sign_content_for_user_sign(json)
    return verify(content, signature)
  end

  def gen_private_map_key(user_id, room_id, expire = 300)
    userbuf = ""
    userbuf << [0].pack('C1') #
    idlen =  user_id.to_s.length
    userbuf << [idlen].pack('n')
    userbuf << [user_id.to_s].pack("a#{idlen}")
    userbuf << [sdk_app_id.to_i].pack("N")
    userbuf << [room_id].pack('N')
    userbuf << [Time.now.to_i + expire].pack('N')
    userbuf << ["0xff".hex].pack('N')
    userbuf << [0].pack('N')

    json = {
      'TLS.account_type' => '0',
      'TLS.identifier' => user_id.to_s,
      'TLS.appid_at_3rd' => '0',
      'TLS.sdk_appid' => sdk_app_id.to_s,
      'TLS.expire_after' => expire.to_s,
      'TLS.version' => '201512300000',
      'TLS.time' => Time.now.to_i.to_s,
      'TLS.userbuf' => Base64.strict_encode64(userbuf)
    }
    content = gen_sign_content_for_private_map_key(json)
    signature = sign(content)
    json['TLS.sig'] = Base64.strict_encode64(signature)
    if json['TLS.sig'].nil?
      raise "sig base64 error"
    end
    json_str = JSON.generate(json)
    data = Zlib::Deflate.deflate(json_str)
    return base64_encode(data)
  end

  def verify_private_map_key(private_map_key, user_id)
    data = base64_decode(private_map_key)
    json_str = Zlib::Inflate.inflate(data)
    json = JSON.parse(json_str)
    if json['TLS.identifier'] != user_id.to_s
      raise "identifier not match, identifier: #{ json['TLS.identifier']}, user_id: #{user_id}"
    end
    if json['TLS.sdk_appid'] != sdk_app_id.to_s
      raise "sdk_appid not match, sdk_appid: #{ json['TLS.sdk_appid']}, sdk_app_id: #{sdk_app_id}"
    end
    signature = Base64.strict_decode64(json['TLS.sig'])
    if signature.nil?
      raise "userSig json decode error"
    end
    content = gen_sign_content_for_private_map_key(json)
    return verify(content, signature)
  end

  private

  def sign(content)
    digest = OpenSSL::Digest::SHA256.digest(content)
    pkey = OpenSSL::PKey.read(private_key)
    pkey.dsa_sign_asn1(digest)
  end

  def verify(content, sig)
    digest = OpenSSL::Digest::SHA256.digest(content)
    pkey = OpenSSL::PKey.read(public_key)
    pkey.dsa_verify_asn1(digest, sig)
  end


  def gen_sign_content_for_user_sig(json)
    return ['TLS.appid_at_3rd', 'TLS.account_type', 'TLS.identifier', 'TLS.sdk_appid', 'TLS.time', 'TLS.expire_after'].map do  |k|
      v = json[k]
      "#{k}:#{v}\n"
    end.join('')
  end

  def gen_sign_content_for_private_map_key(json)
    return ['TLS.appid_at_3rd', 'TLS.account_type', 'TLS.identifier', 'TLS.sdk_appid', 'TLS.time', 'TLS.expire_after', 'TLS.userbuf'].map do  |k|
      v = json[k]
      "#{k}:#{v}\n"
    end.join('')
  end

  def base64_encode(str)
    en_str = Base64.strict_encode64(str)
    en_str.gsub(/\+/, '*').gsub(/\//, '-').gsub(/\=/, '_')
  end

  def base64_decode(str)
    de_str = str.gsub(/\*/, '+').gsub(/\-/, '/').gsub(/\_/, '=')
    Base64.strict_decode64(de_str)
  end
end


sdk_app_id = 1400037025
room_id = 10000
user_id = 'webrtc98'

private_key = File.read(File.expand_path("./private_key"))
public_key = File.read(File.expand_path("./public_key"))

#初始化WebrtcApi
api = WebrtcSigApi.new(sdk_app_id, private_key, public_key)


p "private_map_key:"
pmk = api.gen_private_map_key(user_id, room_id)
p pmk
p "user_sig:"
us = api.gen_user_sig(user_id)
p us
p "verify private_map_key:"
p api.verify_private_map_key(pmk, user_id)
p "verify user_sig:"
p api.verify_user_sig(us, user_id)

