# encoding: utf-8
require 'spec_helper'
require 'logstash/filters/bitflags'

describe LogStash::Filters::Bitflags do
  
    let(:config) { Hash.new }
    subject { described_class.new(config) }
    
    describe "decimal decoding" do
        let(:config) do
          {
            "field"       => "input",
            "destination" => "output",
            "dictionary"  => [ 1, "Flag_1",
                               2, "Flag_2",
                               4, "Flag_4",
                               8, "Flag_8",
                               64, "Flag_64" ]
          }
	    end
	    
	    context "single match" do 
            let(:event) { LogStash::Event.new("input" => 1) }
            
            it "decodes a decimal input value to a single flag strings" do
              subject.register
              subject.filter(event)
              expect(event.get("output")).to eq(["Flag_1"])
              expect(event.get("tags")).to eq(nil)
            end
	    end
	    
	    context "multiple match" do 
            let(:event) { LogStash::Event.new("input" => 71) }
            
            it "decodes a decimal input value to a list of flag strings" do
              subject.register
              subject.filter(event)
              expect(event.get("output")).to eq(["Flag_1", "Flag_2", "Flag_4", "Flag_64"])
              expect(event.get("tags")).to eq(nil)
            end
	    end
        
	    context "no match" do 	
	        let(:event) { LogStash::Event.new("input" => 32) }
        
            it "decodes a decimal input value with no match" do
                subject.register
                subject.filter(event)
                expect(event.get("output")).to eq([])
                expect(event.get("tags")).to eq(nil)
            end
        end	
    end

    describe "hex decoding" do
        let(:config) do
          {
            "field"       => "input",
            "destination" => "output",
            "dictionary"  => [ 0x1, "Flag_x1",
                               0x2, "Flag_x2",
                               0x4, "Flag_x4",
                               0x8, "Flag_x8",
                               0x40, "Flag_x40" ]
          }
	    end
	    
	    context "single match" do 
            let(:event) { LogStash::Event.new("input" => 0x1) }
            
            it "decodes a hexidecimal input value to single flag string" do
                subject.register
                subject.filter(event)
                expect(event.get("output")).to eq(["Flag_x1"])			  
                expect(event.get("tags")).to eq(nil)
            end
	    end
	    
	    context "multiple match" do 
            let(:event) { LogStash::Event.new("input" => 0x47) }
            
            it "decodes a hexidecimal input value to a list of flag strings" do
                subject.register
                subject.filter(event)
                expect(event.get("output")).to eq(["Flag_x1", "Flag_x2", "Flag_x4", "Flag_x40"])
                expect(event.get("tags")).to eq(nil)
            end
	    end
        
	    context "no match" do 	
	        let(:event) { LogStash::Event.new("input" => 0x20) }
        
            it "decodes an hexidecimal input value with no match" do
                subject.register
                subject.filter(event)
                expect(event.get("output")).to eq([])
                expect(event.get("tags")).to eq(nil)
            end
        end	
    end
	
	
	describe "mixed decoding" do
        let(:config) do
          {
            "field"       => "input",
            "destination" => "output",
            "dictionary"  => [ 1, "Flag_1",
                               2, "Flag_2",
                               4, "Flag_4",
                               8, "Flag_8",
                               64, "Flag_64" ]
          }
	    end
	    
	    context "single match" do 
            let(:event) { LogStash::Event.new("input" => '0x1') }
            
            it "decodes a decimal input value to a single flag strings" do
              subject.register
              subject.filter(event)
              expect(event.get("output")).to eq(["Flag_1"])
              expect(event.get("tags")).to eq(nil)
            end
	    end
	    
	    context "multiple match" do 
            let(:event) { LogStash::Event.new("input" => 0x47) }
            
            it "decodes a decimal input value to a list of flag strings" do
              subject.register
              subject.filter(event)
              expect(event.get("output")).to eq(["Flag_1", "Flag_2", "Flag_4", "Flag_64"])
              expect(event.get("tags")).to eq(nil)
            end
	    end
        
	    context "no match" do 	
	        let(:event) { LogStash::Event.new("input" => 0x20) }
        
            it "decodes a decimal input value with no match" do
                subject.register
                subject.filter(event)
                expect(event.get("output")).to eq([])
                expect(event.get("tags")).to eq(nil)
            end
        end	
    end
	
	
	describe "tag on failure" do
        let(:config) do
          {
            "field"       => "input",
            "destination" => "output",
            "dictionary"  => [ 1, "Flag_1",
                               2, "Flag_2",
                               4, "Flag_4",
                               8, "Flag_8",
                               64, "Flag_1" ]
          }
	    end
	    
	    context "duplicate flags" do 
            let(:event) { LogStash::Event.new("input" => 1) }
            
            it "detects and tags duplicate flags error" do
              subject.register
              subject.filter(event)
              expect(event.get("output")).to eq([])	
              expect(event.get("tags")).to eq(["_flagparsefailure"])	
            end
	    end		
    end
	
	describe "tag on failure" do
        let(:config) do
          {
            "field"       => "input",
            "destination" => "output",
            "dictionary"  => [ 1, "Flag_1",
                               2, "Flag_2",
                               4, "Flag_4",
                               8, "Flag_8",
                               1, "Flag_64" ]
          }
	    end
	    
	    context "duplicate keys" do 
            let(:event) { LogStash::Event.new("input" => 1) }
            
            it "detects and tags duplicate keys error" do
              subject.register
              subject.filter(event)
              expect(event.get("output")).to eq([])	
              expect(event.get("tags")).to eq(["_flagparsefailure"])	
            end
	    end		
    end
	
	describe "tag on failure" do
        let(:config) do
          {
            "field"       => "input",
            "destination" => "output",
            "dictionary"  => [ 1, "Flag_1",
                               2, "Flag_2",
                               "4", "Flag_4",
                               8, "Flag_8",
                               64, "Flag_64" ]
          }
	    end
	    
	    context "invalid keys" do 
            let(:event) { LogStash::Event.new("input" => 1) }
            
            it "detects and tags invalid key data error" do
              subject.register
              subject.filter(event)
              expect(event.get("output")).to eq([])	
              expect(event.get("tags")).to eq(["_flagparsefailure"])	
            end
	    end		
    end
	
	describe "tag on failure" do
        let(:config) do
          {
            "field"       => "input",
            "destination" => "output",
            "dictionary"  => [ 1, "Flag_1",
                               2, "Flag_2",
                               4, 4,
                               8, "Flag_8",
                               64, "Flag_64" ]
          }
	    end
	    
	    context "invalid flags" do 
            let(:event) { LogStash::Event.new("input" => 1) }
            
            it "detects and tags invalid flag data error" do
              subject.register
              subject.filter(event)
              expect(event.get("output")).to eq([])	
              expect(event.get("tags")).to eq(["_flagparsefailure"])	
            end
	    end		
    end
	
	describe "tag on failure" do
        let(:config) do
          {
            "field"       => "input",
            "destination" => "output",
            "dictionary"  => [ 1, "Flag_1",
                               2, "Flag_2",
                               4, 4,
                               8, "Flag_8",
                               64, "Flag_64" ],
            "tag_on_failure" => ["_custom"]
          }
	    end
	    
	    context "custom parse failure tag" do 		
            let(:event) { LogStash::Event.new("input" => 1) }
            
            it "detects invalid flag data error and applies a custom tag" do
              subject.register
              subject.filter(event)
              expect(event.get("output")).to eq([])	
              expect(event.get("tags")).to eq(["_custom"])	
            end
	    end		
    end
	
	describe "tag on failure" do
        let(:config) do
          {
            "field"       => "input",
            "destination" => "output",
            "dictionary"  => [ 1, "Flag_1",
                               2, "Flag_2",
                               4, 4,
                               8, "Flag_8",
                               64, "Flag_64" ],
            "tag_on_failure" => ["_custom", "_extra_tag"]
          }
	    end
	    
	    context "custom parse failure with multiple tags" do 		
            let(:event) { LogStash::Event.new("input" => 1) }
            
            it "detects invalid flag data error and applies a custom tag" do
              subject.register
              subject.filter(event)
              expect(event.get("output")).to eq([])	
              expect(event.get("tags")).to eq(["_custom", "_extra_tag"])	
            end
	    end		
    end
  
end
