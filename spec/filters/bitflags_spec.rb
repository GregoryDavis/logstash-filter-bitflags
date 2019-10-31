# encoding: utf-8
require 'spec_helper'
require 'logstash/filters/bitflags'

describe LogStash::Filters::Bitflags do
  
    let(:config) { Hash.new }
    subject { described_class.new(config) }
    
    describe "using a dictionary file" do
        let(:config) do
          {
            "field"       => "input",
            "destination" => "output",
            "dictionary_path"  => "./spec/fixtures/dictionary.yaml"
          }
	    end
	    
	    context "single match" do 
            let(:event) { LogStash::Event.new("input" => 1) }
            
            it "return 1 matching value" do
              subject.register
              subject.filter(event)
              expect(event.get("output")).to eq(["Flag_1"])
              expect(event.get("tags")).to eq(nil)
            end
	    end
	    
	    context "multiple match" do 
            let(:event) { LogStash::Event.new("input" => 71) }
            
            it "return all matching values" do
              subject.register
              subject.filter(event)
              expect(event.get("output")).to eq(["Flag_1", "Flag_2", "Flag_4", "Flag_64"])
              expect(event.get("tags")).to eq(nil)
            end
	    end
        
	    context "no match" do 	
	        let(:event) { LogStash::Event.new("input" => 32) }
        
            it "return 0 matching values" do
                subject.register
                subject.filter(event)
                expect(event.get("output")).to eq([])
                expect(event.get("tags")).to eq(nil)
            end
        end	
    end
    
    describe "using a hexidecimal dictionary file" do
        let(:config) do
          {
            "field"       => "input",
            "destination" => "output",
            "dictionary_path"  => "./spec/fixtures/hex_dictionary.yaml"
          }
	    end
	    
	    context "single match" do 
            let(:event) { LogStash::Event.new("input" => 1) }
            
            it "return 1 matching value" do
              subject.register
              subject.filter(event)
              expect(event.get("output")).to eq(["Flag_1"])
              expect(event.get("tags")).to eq(nil)
            end
	    end
	    
	    context "multiple match" do 
            let(:event) { LogStash::Event.new("input" => 71) }
            
            it "return all matching value" do
              subject.register
              subject.filter(event)
              expect(event.get("output")).to eq(["Flag_1", "Flag_2", "Flag_4", "Flag_64"])
              expect(event.get("tags")).to eq(nil)
            end
	    end
        
	    context "no match" do 	
	        let(:event) { LogStash::Event.new("input" => 32) }
        
            it "return 0 matching values" do
                subject.register
                subject.filter(event)
                expect(event.get("output")).to eq([])
                expect(event.get("tags")).to eq(nil)
            end
        end	
    end
    
    describe "using an input dictionary" do
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
            
            it "return 1 matching value" do
              subject.register
              subject.filter(event)
              expect(event.get("output")).to eq(["Flag_1"])
              expect(event.get("tags")).to eq(nil)
            end
	    end
	    
	    context "multiple match" do 
            let(:event) { LogStash::Event.new("input" => 71) }
            
            it "return all matching value" do
              subject.register
              subject.filter(event)
              expect(event.get("output")).to eq(["Flag_1", "Flag_2", "Flag_4", "Flag_64"])
              expect(event.get("tags")).to eq(nil)
            end
	    end
        
	    context "no match" do 	
	        let(:event) { LogStash::Event.new("input" => 32) }
        
            it "return 0 matching values" do
                subject.register
                subject.filter(event)
                expect(event.get("output")).to eq([])
                expect(event.get("tags")).to eq(nil)
            end
        end	
    
        context "hexidecimal input single match" do 
            let(:event) { LogStash::Event.new("input" => '0x1') }
            
            it "return 1 matching value" do
              subject.register
              subject.filter(event)
              expect(event.get("output")).to eq(["Flag_1"])
              expect(event.get("tags")).to eq(nil)
            end
	    end
	    
	    context "hexidecimal input multiple match" do 
            let(:event) { LogStash::Event.new("input" => 0x47) }
            
            it "return all matching value" do
              subject.register
              subject.filter(event)
              expect(event.get("output")).to eq(["Flag_1", "Flag_2", "Flag_4", "Flag_64"])
              expect(event.get("tags")).to eq(nil)
            end
	    end
        
	    context "hexidecimal input no match" do 	
	        let(:event) { LogStash::Event.new("input" => 0x20) }
        
            it "return 0 matching values" do
                subject.register
                subject.filter(event)
                expect(event.get("output")).to eq([])
                expect(event.get("tags")).to eq(nil)
            end
        end	
    end

    describe "using a hexidecimal dictionary" do
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

    describe "using the separator configuration" do
        let(:config) do
          {
            "field"       => "input",
            "destination" => "output",
            "dictionary"  => [ 1, "Flag_1",
                               2, "Flag_2",
                               4, "Flag_4",
                               8, "Flag_8",
                               64, "Flag_64" ],
            "separator"   => '|'
          }
	    end
	    
	    context "single match" do 
            let(:event) { LogStash::Event.new("input" => 1) }
            
            it "return 1 matching value as a string" do
              subject.register
              subject.filter(event)
              expect(event.get("output")).to eq("Flag_1")
              expect(event.get("tags")).to eq(nil)
            end
	    end
	    
	    context "multiple match" do 
            let(:event) { LogStash::Event.new("input" => 71) }
            
            it "return all matching values as a string" do
              subject.register
              subject.filter(event)
              expect(event.get("output")).to eq("Flag_1|Flag_2|Flag_4|Flag_64")
              expect(event.get("tags")).to eq(nil)
            end
	    end
        
	    context "no match" do 	
	        let(:event) { LogStash::Event.new("input" => 32) }
        
            it "return an empty string" do
                subject.register
                subject.filter(event)
                expect(event.get("output")).to eq("")
                expect(event.get("tags")).to eq(nil)
            end
        end	
    end
	    
    describe "using the override default configuration" do
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
	    
	    context "destination is free" do 
            let(:event) { LogStash::Event.new("input" => 1) }
            
            it "reurn the matched value" do
              subject.register
              subject.filter(event)
              expect(event.get("output")).to eq(["Flag_1"])
              expect(event.get("tags")).to eq(nil)
            end
	    end
	    
	    context "destination is occupied" do 
            let(:event) { LogStash::Event.new("input" => 1, "output" => "100") }
            
            it "return the original value" do
              subject.register
              subject.filter(event)
              expect(event.get("output")).to eq("100")
              expect(event.get("tags")).to eq(nil)
            end
	    end
        
	    context "no match" do 	
	        let(:event) { LogStash::Event.new("input" => 32, "output" => "100") }
        
            it "return the original value" do
                subject.register
                subject.filter(event)
                expect(event.get("output")).to eq("100")
                expect(event.get("tags")).to eq(nil)
            end
        end	
    end
    
    describe "using the override configuration set false" do
        let(:config) do
          {
            "field"       => "input",
            "destination" => "output",
            "dictionary"  => [ 1, "Flag_1",
                               2, "Flag_2",
                               4, "Flag_4",
                               8, "Flag_8",
                               64, "Flag_64" ],
            "override"    => false
          }
	    end
	    
	    context "destination is free" do 
            let(:event) { LogStash::Event.new("input" => 1) }
            
            it "return the matched value" do
              subject.register
              subject.filter(event)
              expect(event.get("output")).to eq(["Flag_1"])
              expect(event.get("tags")).to eq(nil)
            end
	    end
	    
	    context "destination is occupied" do 
            let(:event) { LogStash::Event.new("input" => 1, "output" => "100") }
            
            it "return the original value" do
              subject.register
              subject.filter(event)
              expect(event.get("output")).to eq("100")
              expect(event.get("tags")).to eq(nil)
            end
	    end
        
	    context "no match" do 	
	        let(:event) { LogStash::Event.new("input" => 32, "output" => "100") }
        
            it "return the original value" do
                subject.register
                subject.filter(event)
                expect(event.get("output")).to eq("100")
                expect(event.get("tags")).to eq(nil)
            end
        end	
    end
    
    describe "using the override configuration set true" do
        let(:config) do
          {
            "field"       => "input",
            "destination" => "output",
            "dictionary"  => [ 1, "Flag_1",
                               2, "Flag_2",
                               4, "Flag_4",
                               8, "Flag_8",
                               64, "Flag_64" ],
            "override"    => true
          }
	    end
	    
	    context "destination is free" do 
            let(:event) { LogStash::Event.new("input" => 1) }
            
            it "return the matched value" do
              subject.register
              subject.filter(event)
              expect(event.get("output")).to eq(["Flag_1"])
              expect(event.get("tags")).to eq(nil)
            end
	    end
	    
	    context "return the matched value" do 
            let(:event) { LogStash::Event.new("input" => 1, "output" => "100") }
            
            it "overrides the destination value" do
              subject.register
              subject.filter(event)
              expect(event.get("output")).to eq(["Flag_1"])
              expect(event.get("tags")).to eq(nil)
            end
	    end
        
	    context "no match" do 	
	        let(:event) { LogStash::Event.new("input" => 32, "output" => "100") }
        
            it "return an empty array" do
                subject.register
                subject.filter(event)
                expect(event.get("output")).to eq([])
                expect(event.get("tags")).to eq(nil)
            end
        end	
    end
	
	describe "validate input dictionary" do
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
            
            it "raises an error" do
              expect{subject.register}.to raise_error
            end
	    end		
    end
	
	describe "validate input dictionary" do
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
            
            it "raises an error" do
              expect{subject.register}.to raise_error
            end
	    end			
    end
	
	describe "validate input dictionary" do
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
            
            it "raises an error" do
              expect{subject.register}.to raise_error
            end
	    end			
    end
	
	describe "validate input dictionary" do
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
            
            it "raises an error" do
              expect{subject.register}.to raise_error
            end
	    end	
    end
  
end
