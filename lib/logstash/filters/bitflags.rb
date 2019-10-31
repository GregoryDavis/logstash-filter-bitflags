# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"

require 'psych'
require 'psych/exception'

# This bitflags filter will translate a numeric input value into
# a sequence of named flags which are match the flag when ANDed
# with the input value.
class LogStash::Filters::Bitflags < LogStash::Filters::Base

  # Setting the config_name here is required. This is how you
  # configure this filter from your Logstash config.
  #
  # filter {
  #   bitflags {
  #     field =>
  #     flags => { 1 => "Flag_1", 2 => "Flag_2", 4 => "Flag_3", 3 => Flags_1_and_2" }
  #   }
  # }
  #
  config_name "bitflags"

  # Input value field to test against flag list
  config :field, :validate => :string, :required => true

  # Target field for output
  config :destination, :validate => :string, :required => true

  # Input dictionary of flags keyed on their numeric value.
  # Keys are assumed to be uniquely convertable to integer
  config :dictionary, :validate => :hash,  :default => {}
    
  # The full path of an external dictionary file. The file format must be a YAML.
  # Keys must be unique and are interpreted as integers, the matching value can be
  # any string.
  #
  # NOTE: `dictionary` and `dictionary_path` cannot both be specified and will
  # generate an error.
  #
  config :dictionary_path, :validate => :string

  # The separator property is an optional string argument which 
  # will cause the filter to return results as a string of 
  # all matching flags name delimited by the specified separator.
  config :separator, :validate => :string
  
  # The override property is an optional boolean argument which 
  # controls the behavior of the filter when the destination 
  # field already exists on the events to be filtered.  When 
  # false, processing terminates, when true the results of the 
  # decoding will overwrite the existing contents of destination.
  config :override, :validate => :boolean, :default => false

  # Append values to the `tags` field if parse failure occurs
  config :tag_on_failure, :validate => :array, :default => ["_flagparsefailure"]

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
