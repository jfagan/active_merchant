module ActiveMerchant #:nodoc:
  module Billing #:nodoc:
    class PayJunctionV2Gateway < Gateway
      self.display_name = "PayJunction"
      self.homepage_url = "https://www.payjunction.com/"

      #self.test_url = "https://api.payjunctionlabs.com/transactions"
      #self.live_url = "https://api.payjunction.com/transactions"

      self.supported_countries = ["US"]
      self.default_currency = "USD"
      self.money_format = :dollars
      self.supported_cardtypes = [:visa, :master, :american_express, :discover]

      attr_accessor :request_logger

      def initialize(options={})
        requires!(options, :api_login, :api_password, :api_key)
        self.request_logger = options[:request_logger] if options.has_key?(:request_logger)
        super
      end

      def purchase(amount, payment_method, options={})
        post = {}
        add_invoice(post, amount, options)
        add_payment_method(post, payment_method)

        #Always run this check
        post[:avs] = "ADDRESS_AND_ZIP"

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

      def store_payment_method(payment_obj, customer_id, billing_address = nil, options = {})
         post = {}

         add_payment_method(post, payment_obj, billing_address, options)
         add_customer_reference(post, customer_id)

         JSON.parse(ssl_invoke("vault", post, :post, options))
      end

      def update_payment_method(payment_obj, customer_id, billing_address = nil, options = {})
         post = {}

         add_payment_method(post, payment_obj, billing_address)
         add_customer_reference(post, customer_id)

         JSON.parse(ssl_invoke("vault", post, :put, options))
      end

      def find_billing_address(gateway_customer_id)
        begin
          JSON.parse(ssl_invoke("address", { gateway_customer_id: gateway_customer_id }, :get))
        rescue => e
          return nil
        end
      end

      def delete_vault(gateway_customer_id, vault_id)
        resp = ssl_invoke("vault", { gateway_customer_id: gateway_customer_id, vault_id: vault_id }, :delete)
      end

      def find_vault_objects(gateway_customer_id)
        JSON.parse(ssl_invoke("vault", { gateway_customer_id: gateway_customer_id }, :get))
      end

      def find_vault_object(gateway_customer_id, vault_id)
        JSON.parse(ssl_invoke("vault", { gateway_customer_id: gateway_customer_id, vault_id: vault_id }, :get))
      end

      def store_customer(customer)
         post = {}

         post[:firstName] = customer.firstname
         post[:lastName] = customer.lastname
         post[:email] = customer.email
         post[:custom1] = customer.pid
         post[:identifier] = '%05i' % customer.client.code.to_i
         post[:companyName] = customer.client.name

         gateway_response = ssl_invoke("customer", post, :post)
         JSON.parse(gateway_response)
      end

      def update_customer(customer)
         put = {}

         put[:gateway_customer_id] = customer.gateway_user_id
         put[:firstName] = customer.firstname
         put[:lastName] = customer.lastname
         put[:email] = customer.email
         put[:custom1] = customer.pid
         put[:identifier] = '%05i' % customer.client.code.to_i
         put[:companyName] = customer.client.name

         gateway_response = ssl_invoke("customer", put, :put)
         JSON.parse(gateway_response)
      end

      def find_customer(gateway_customer_id)
        begin
          JSON.parse(ssl_invoke("customer", { gateway_customer_id: gateway_customer_id }, :get))
        rescue => e
          return nil
        end
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

      def add_payment_method(post, payment_method, billing_address = nil, options = {})
        if payment_method.is_a? Integer
          post[:vaultId] = payment_method
        elsif options.has_key?(:gateway_object_id) && !options[:gateway_object_id].empty?
          post[:vaultId] = options[:gateway_object_id]
        elsif payment_method.is_a? ActiveMerchant::Billing::Check
          post[:achRoutingNumber] = payment_method.routing_number
          post[:achAccountNumber] = payment_method.account_number
          post[:achAccountType] = payment_method.ach_account_type
          post[:achType] = payment_method.ach_type
        else
          post[:cardNumber] = payment_method.number
          post[:cardExpMonth] = format(payment_method.month, :two_digits)
          post[:cardExpYear] = format(payment_method.year, :four_digits)
        end

        if !billing_address.nil?
          post[:address] = billing_address[:address]
          post[:city] = billing_address[:city]
          post[:state] = billing_address[:state]
          post[:zip] = billing_address[:zip]
          post[:country] = billing_address[:country]
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

      #TODO Refactor this mess of code ASAP
      def ssl_invoke(action, params, method = nil, options = {})
        if ["purchase", "authorize", "refund", "credit"].include?(action)
          log_request({endpoint: url(), headers: headers, action_type: action, method: "POST", params: params})
          ssl_post(url(), post_data(params), headers)
        elsif ["customer"].include?(action) && [:get, :post, :put].include?(method)
          if method == :post
            log_request({endpoint: customer_url, headers: headers, action_type: action, method: "POST", params: params})
            ssl_request(method, customer_url, post_data(params), headers)
          elsif method == :put
            log_request({endpoint: customer_url(params[:gateway_customer_id]), headers: headers, action_type: action, method: "PUT", params: params})
            ssl_request(method, customer_url(params[:gateway_customer_id]), post_data(params), headers)
          else
            log_request({endpoint: customer_url(params[:gateway_customer_id]), headers: headers, action_type: action, method: method, params: params})
            ssl_get(customer_url(params[:gateway_customer_id]), headers)
          end
        elsif ["vault"].include?(action)
          if method.to_sym == :post
            log_request({endpoint: vault_url(params[:customerId]), headers: headers, action_type: action, method: "POST", params: ""})
            ssl_post(vault_url(params[:customerId]), post_data(params), headers)
          elsif method.to_sym == :put
            log_request({endpoint: vault_url(params[:customerId], options[:gateway_object_id]), headers: headers, action_type: action, method: "PUT", params: ""})
            ssl_request(:put, vault_url(params[:customerId], options[:gateway_object_id]), post_data(params), headers)
          elsif method.to_sym == :delete
            log_request({endpoint: vault_url(params[:gateway_customer_id], (params[:vault_id] || nil)), headers: headers, action_type: action, method: "DELETE", params: params})
            ssl_request(:delete, vault_url(params[:gateway_customer_id], (params[:vault_id] || nil)), nil, headers)
          else
            log_request({endpoint: vault_url(params[:gateway_customer_id], (params[:vault_id] || nil)), headers: headers, action_type: action, method: method, params: params})
            ssl_get(vault_url(params[:gateway_customer_id], (params[:vault_id] || nil)), headers)
          end
        else
          log_request({endpoint: url(params), headers: headers, action_type: action, method: "PUT", params: params})
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
        local_url = "#{url.gsub('transactions','customers')}"
        gateway_customer_id.blank? ? local_url : "#{local_url}/#{gateway_customer_id}"
      end

      def vault_url(gateway_customer_id, vault_id = nil)
        local_url = url.gsub('transactions', ('customers/' + gateway_customer_id.to_s + '/vaults/'))
        vault_id.nil? ? local_url : "#{local_url}#{vault_id}"
      end

      def url(params={})
        params.has_key?(:transactionId) ? "#{ENV['PAYMENT_GATEWAY_URL']}/#{params[:transactionId]}" : "#{ENV['PAYMENT_GATEWAY_URL']}"
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

      def log_request(params = {})
        return if !defined?(@request_logger) || !@request_logger.respond_to?(:log!)
        @request_logger.log!({method: params[:method].to_s, params: params[:params], endpoint: params[:endpoint], headers: params[:headers], action_type: params[:action_type]})
      end
    end
  end
end
