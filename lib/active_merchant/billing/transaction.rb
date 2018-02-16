module ActiveMerchant
  module Billing
    class Transaction
      attr_accessor :response

      def initialize(params = {})
        @response = parse_data(params)
      end

      def valid?
        @response.present?
      end

      def settled?
        @response.settlement.settled
      end

      def parse_data(gateway_json)
        JSON.parse(gateway_json.to_json, object_class: OpenStruct)
      end

    end
  end
end
