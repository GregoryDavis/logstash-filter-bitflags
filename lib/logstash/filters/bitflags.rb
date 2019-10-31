# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"

require 'psych'
require 'psych/exception'

# This bitflags filter will translate a numeric input value into
# a sequence of named flags which are match the flag when ANDed
# with the input value.
class LogStash::Filters::Bitflags < LogStash::Filters::Base
    config_name "bitflags"

    # The name of the logstash event field containing the value to be decoded by
    # the bitflags filter (e.g. `input`, `flags`, `file_code`).
    config :field, :validate => :string, :required => true
    
    # If the destination (or target) field already exists, this configuration 
    # item specifies whether the filter should skip decoding  (default) or 
    # overwrite the target field with the decoded result.
    config :override, :validate => :boolean, :default => false

    # The destination field to store the decoded flags. Set this to the same 
    # as the source to substitute decoded results for the original value.
    config :destination, :validate => :string, :required => true
  
  # The dictionary to use for translation, when specified in the logstash filter
    # The dictionary to use for decoding, when specified in the logstash filter
    # configuration item.  Duplicate values are not permitted.  
    #
    # Example:
    # [source,ruby]
    #     filter {
    #       %PLUGIN% {
    #         dictionary => [ 0x1, "Flag_1",
    #                         0x2, "Flag_2",
    #                         0x4, "Flag_3" ]
    #       }
    #     }
    #
    # NOTE: `dictionary` and `dictionary_path` cannot both be specified and will
    # generate an error.
    config :dictionary, :validate => :hash,  :default => {}

    # The full path of an external dictionary file, in YAML format.
    # Keys must be unique and are interpreted as integers, the matching value
    # can be any unique string.
    #
    # Example:
    # [source,ruby]
    #     0x1: "Flag_1"
    #     0x2: "Flag_2"
    #     0x4: "Flag_3"
    #
    # NOTE: `dictionary` and `dictionary_path` cannot both be specified and will
    # generate an error.
    #
    config :dictionary_path, :validate => :string

    # By default, decoded results are returned as an array of strings. The 
    # separator property is an optional string argument which, when set, will
    # results to be returned as a string of all values, delimited by the 
    # specified separator.
    config :separator, :validate => :string

    public
    def register
        if @dictionary_path && !@dictionary.empty?
            raise LogStash::ConfigurationError, I18n.t(
            "logstash.agent.configuration.invalid_plugin_register",
            :plugin => "filter",
            :type => "bitflags",
            :error => "The configuration options 'dictionary' and 'dictionary_path' cannot be used together"
            )
        end

        if @dictionary_path
            @flag_lookup = Psych.load_file(@dictionary_path)
        else
            @flag_lookup = @dictionary
        end

        if not flags_are_valid?(@flag_lookup)
            raise LogStash::ConfigurationError, I18n.t(
            "logstash.agent.configuration.invalid_plugin_register",
            :plugin => "filter",
            :type => "bitflags",
            :error => "Dictionary keys are required to be integers"
            )
        end

    end # def register

    public
    def filter(event)
        # If the destination field is alredy populated and @override is not set
        # true, no further work should be done.
        return unless @override or !event.include?(@destination)

        # Force unknown input to string type to allow determination of
        # the appropriate base for to_i conversion.
        input = event.get(@field).to_s
        base = input.start_with?('0x') ? 16 : 10
        value = input.to_i(base)

        flag_list = list_flags(@flag_lookup, value)

        if not separator.nil?
            flag_list = flag_list.join(separator)
        end

        event.set(@destination, flag_list)

        # correct debugging log statement for reference
        # using the event.get API
        @logger.debug? && @logger.debug("Output flags: #{event.get("@destination")}")

        # filter_matched should go in the last line of our successful code
        filter_matched(event)
    end # def filter

    private
    def flags_are_valid? (flag_hash)
        valid_keys  = flag_hash.keys.reduce (true) { |valid, key| valid && key.kind_of?(Integer) }
        valid_flags = flag_hash.values.reduce (true) { |valid, value| valid && value.kind_of?(String) }
        valid_flags = valid_flags && flag_hash.values.uniq.length == flag_hash.values.length

        return valid_keys && valid_flags
    end

    private
    def list_flags(flag_hash, value)
        return flag_hash.keys.select{|key| key & value == key}.map{|key| flag_hash[key]}
    end

end # class LogStash::Filters::Bitfield
