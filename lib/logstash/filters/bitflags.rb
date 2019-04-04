# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"

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
  config :dictionary, :validate => :hash, :required => true  
  
  # Append values to the `tags` field if parse failure occurs 
  config :tag_on_failure, :validate => :array, :default => ["_flagparsefailure"]

  public
  def register
    # Add instance variables
  end # def register

  public
  def filter(event)
    # no validation on the input field
    value = event.get(@field).to_i
  
    if flags_are_valid?(@dictionary) 	  
      event.set(@destination, list_flags(@dictionary, value))

	  # correct debugging log statement for reference
      # using the event.get API
      @logger.debug? && @logger.debug("Output flags: #{event.get("@destination")}")
	else
      event.set(@destination, [])
      @tag_on_failure.each {|tag| event.tag(tag)}
	end

    # filter_matched should go in the last line of our successful code
    filter_matched(event)
  end # def filter
  
  private
  def flags_are_valid? ( flag_hash )
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
