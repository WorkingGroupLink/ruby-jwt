# frozen_string_literal: true

require 'jwt/security_utils'
require 'openssl'
require 'jwt/algos/hmac'
require 'jwt/algos/eddsa'
require 'jwt/algos/ecdsa'
require 'jwt/algos/rsa'
require 'jwt/algos/ps'
require 'jwt/algos/unsupported'
begin
  require 'rbnacl'
rescue LoadError
  raise if defined?(RbNaCl)
end

# JWT::Signature module
module JWT
  # Signature logic for JWT
  module Signature
    extend self
    ALGOS = [
      Algos::Hmac,
      Algos::Ecdsa,
      Algos::Rsa,
      Algos::Eddsa,
      Algos::Ps,
      Algos::Unsupported
    ].freeze
    ToSign = Struct.new(:algorithm, :msg, :key)
    ToVerify = Struct.new(:algorithm, :public_key, :signing_input, :signature)

    def sign(algorithm, msg, key)
      algo = ALGOS.find do |alg|
        alg.const_get(:SUPPORTED).include? algorithm
      end
      algo.sign ToSign.new(algorithm, msg, key)
    end

    def verify(algorithm, key, signing_input, signature)
      raise JWT::DecodeError, 'No verification key available' unless key

      algo = ALGOS.find do |alg|
        alg.const_get(:SUPPORTED).include? algorithm
      end
      verified = algo.verify(ToVerify.new(algorithm, key, signing_input, signature))
      error_message = 'Signature verification raised when verified is false ' + OpenSSL.errors.inspect
      raise(JWT::VerificationError, error_message) unless verified
    rescue OpenSSL::PKey::PKeyError => e
      error_message = 'Signature verification raised OpenSSL::PKey::PKeyError ' + e.full_message + " " + OpenSSL.errors.inspect
      raise JWT::VerificationError, error_message
    ensure
      OpenSSL.errors.clear
    end
  end
end
