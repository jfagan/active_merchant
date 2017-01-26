module ActiveMerchant #:nodoc:
  module Billing #:nodoc:
    class PayJunctionV2Gateway < Gateway
      self.display_name = "PayJunction"
      self.homepage_url = "https://www.payjunction.com/"

      self.test_url = "https://api.payjunctionlabs.com/transactions"
      self.live_url = "https://api.payjunction.com/transactions"

      self.supported_countries = ["US"]
      self.default_currency = "USD"
      self.money_format = :dollars
      self.supported_cardtypes = [:visa, :master, :american_express, :discover]

      def initialize(options={})
        requires!(options, :api_login, :api_password, :api_key)
        super
      end

      def purchase(amount, payment_method, options={})
        post = {}
        add_invoice(post, amount, options)
        add_payment_method(post, payment_method)

        commit("purchase", post)
      end

      def authorize(amount, payment_method, options={})
        post = {}
        post[:status] = "HOLD"
        add_invoice(post, amount, options)
        add_payment_method(post, payment_method)

        commit("authorize", post)
      end

      def capture(amount, authorization, options={})
        post = {}
        post[:status] = "CAPTURE"
        post[:transactionId] = authorization
        add_invoice(post, amount, options)

        commit("capture", post)
      end

      def void(authorization, options={})
        post = {}
        post[:status] = "VOID"
        post[:transactionId] = authorization

        commit("void", post)
      end

      def refund(amount, authorization, options={})
        post = {}
        post[:action] = "REFUND"
        post[:transactionId] = authorization
        add_invoice(post, amount, options)

        commit("refund", post)
      end

      def credit(amount, payment_method, options={})
        post = {}
        post[:action] = "REFUND"
        add_invoice(post, amount, options)
        add_payment_method(post, payment_method)

        commit("credit", post)
      end

      def verify(credit_card, options={})
        MultiResponse.run(:use_first_response) do |r|
          r.process { authorize(100, credit_card, options) }
          r.process(:ignore_result) { void(r.authorization, options) }
        end
      end

      def store_payment_method(payment_obj, customer_id, billing_address = "", options = {})
         post = {}

         add_payment_method(post, payment_obj)
         #add_billing_address(post, billing_address)
         add_customer_reference(post, customer_id)

         JSON.parse(ssl_invoke("vault", post, :post))
      end

      def delete_vault(gateway_customer_id, vault_id)
        resp = ssl_invoke("vault", { gateway_customer_id: gateway_customer_id, vault_id: vault_id }, :delete)
      end

      def find_vault_objects(gateway_customer_id)
        JSON.parse(ssl_invoke("vault", { gateway_customer_id: gateway_customer_id }, :get))
      end

      def store_customer(customer)
         post = {}

         post[:firstName] = customer.firstname,
         post[:lastName] = customer.lastname,
         post[:email] = customer.email,
         post[:custom1] = customer.pid,

         gateway_response = ssl_invoke("customer", post, :post)
         JSON.parse(gateway_response)
      end

      def find_customer(gateway_customer_id)
        JSON.parse(ssl_invoke("customer", { gateway_customer_id: gateway_customer_id }, :get))
      end

      def supports_scrubbing?
        true
      end

      def scrub(transcript)
        transcript.
          gsub(%r((Authorization: Basic )\w+), '\1[FILTERED]').
          gsub(%r((X-Pj-Application-Key: )[\w-]+), '\1[FILTERED]').
          gsub(%r((cardNumber=)\d+), '\1[FILTERED]').
          gsub(%r((cardCvv=)\d+), '\1[FILTERED]')
      end

      #private

      def add_invoice(post, money, options)
        post[:amountBase] = amount(money) if money
        post[:invoiceNumber] = options[:order_id] if options[:order_id]
      end

      def add_customer_reference(post, customer_id)
        post[:customerId] = customer_id
      end

      def add_payment_method(post, payment_method)
        if payment_method.is_a? Integer
          #post[:transactionId] = payment_method
          post[:vaultId] = payment_method
        elsif payment_method.is_a? ActiveMerchant::Billing::Check
          post[:achRoutingNumber] = payment_method.routing_number
          post[:achAccountNumber] = payment_method.account_number
          post[:achAccountType] = payment_method.account_type
          post[:achType] = "PPD"
        else
          post[:cardNumber] = payment_method.number
          post[:cardExpMonth] = format(payment_method.month, :two_digits)
          post[:cardExpYear] = format(payment_method.year, :four_digits)
          post[:cardCvv] = payment_method.verification_value
        end
      end

      def commit(action, params)
        response = begin
          parse(ssl_invoke(action, params))
        rescue ResponseError => e
          parse(e.response.body)
        end

        success = success_from(response)
        Response.new(
          success,
          message_from(response),
          response,
          authorization: success ? authorization_from(response) : nil,
          error_code: success ? nil : error_from(response),
          test: test?
        )
      end

      def ssl_invoke(action, params, method = nil)
        if ["purchase", "authorize", "refund", "credit"].include?(action)
          ssl_post(url(), post_data(params), headers)
        elsif ["customer"].include?(action) && [:get, :post].include?(method)
          if method == :post
            ssl_request(method, customer_url, post_data(params), headers)
          else
            ssl_get(customer_url(params[:gateway_customer_id]), headers)
          end
        elsif ["vault"].include?(action)
          if method.to_sym == :post
            ssl_post(vault_url(params[:customerId]), post_data(params), headers)
          elsif method.to_sym == :delete
            ssl_request(:delete, vault_url(params[:gateway_customer_id], (params[:vault_id] || nil)), nil, headers)
          else
            ssl_get(vault_url(params[:gateway_customer_id], (params[:vault_id] || nil)), headers)
          end
        else
          ssl_request(:put, url(params), post_data(params), headers)
        end
      end

      def headers
        {
          "Authorization" => "Basic " + Base64.encode64("#{@options[:api_login]}:#{@options[:api_password]}").strip,
          "Content-Type"  => "application/x-www-form-urlencoded;charset=UTF-8",
          "Accept"  => "application/json",
          "X-PJ-Application-Key"  => "#{@options[:api_key]}"
        }
      end

      def post_data(params)
        params.map {|k, v| "#{k}=#{CGI.escape(v.to_s)}"}.join('&')
      end

      def customer_url(gateway_customer_id = nil)
        url = test? ? "#{test_url.gsub('transactions','customers')}" : "#{live_url.gsub('transactions','customers')}"
        gateway_customer_id.blank? ? url : "#{url}/#{gateway_customer_id}"
      end

      def vault_url(gateway_customer_id, vault_id = nil)
        url = test? ? test_url.gsub('transactions', ('customers/' + gateway_customer_id.to_s + '/vaults/')) : live_url.gsub('transactions', ('customers/' + gateway_customer_id.to_s + '/vaults'))
        vault_id.nil? ? url : "#{url}#{vault_id}"
      end

      def url(params={})
        test? ? "#{test_url}/#{params[:transactionId]}" : "#{live_url}/#{params[:transactionId]}"
      end

      def parse(body)
        begin
          JSON.parse(body)
        rescue JSON::ParserError
          message = "Invalid JSON response received from PayJunctionV2Gateway. Please contact PayJunctionV2Gateway if you continue to receive this message."
          message += " (The raw response returned by the API was #{body.inspect})"
          {
            "errors" => [{
              "message" => message
            }]
          }
        end
      end

      def success_from(response)
        return response["response"]["approved"] if response["response"]
        false
      end

      def message_from(response)
        return response["response"]["message"] if response["response"]

        response["errors"].inject(""){ |message,error| error["message"] + "|" + message } if response["errors"]
      end

      def authorization_from(response)
        response["transactionId"]
      end

      def error_from(response)
        response["response"]["code"] if response["response"]
      end
    end
  end
end
