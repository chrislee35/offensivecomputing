require 'helper'
require 'digest/md5'
require 'pp'

class TestOffensivecomputing < Test::Unit::TestCase
	should "log into OC and search for 4462aae981360f73b0016d69029321b4" do
		fail "You must set OCUSER and OCPASS in your environment before running tests\nE.g.\nexport OCUSER=\"l33tsloth\"\nexport OCPASS=\"n3v3r+f33r\"\n" unless ENV['OCUSER'] and ENV['OCPASS']
		oc = OffensiveComputing::MalwareSearch.new(ENV['OCUSER'], ENV['OCPASS'])
		recs = oc.search("4462aae981360f73b0016d69029321b4")
		assert_equal(1, recs.length)
		rec = recs[0]
		assert_equal(
			["4462aae981360f73b0016d69029321b4",
				"f8229be77c429c84f4c612a4f106bc54a96a8733",
				"f951deff6086a1e68f0d09bd3856f1c1af5c117590443ea05d171a75969bbb63",
				"4462aae981360f73b0016d69029321b4.EXE",
				"Sat May 26 17:38:23 UTC 2007",
				"MZ executable for MS-DOS", 
				nil,
				nil], [rec.md5,rec.sha1,rec.sha256,rec.filename,rec.added.to_s,rec.magic,rec.packer,rec.tags])
		file = "test/test.bin"
		dl = rec.download(file)
		assert_equal(1277,dl.length)
		assert_equal(1277,File.size(file))
		assert_equal("103835290aa6daa55d270bf3dde84271",Digest::MD5.hexdigest(dl))
		assert_equal("103835290aa6daa55d270bf3dde84271",Digest::MD5.hexdigest(File.open(file).read))
		if File.exists? file
			File.unlink(file)
		end
	end
	should "log into OC and search for \"conficker\"" do
		fail "You must set OCUSER and OCPASS in your environment before running tests\nE.g.\nexport OCUSER=\"l33tsloth\"\nexport OCPASS=\"n3v3r+f33r\"\n" unless ENV['OCUSER'] and ENV['OCPASS']
		oc = OffensiveComputing::MalwareSearch.new(ENV['OCUSER'], ENV['OCPASS'])
		recs = oc.search("conficker")
		assert_equal(4, recs.length)
	end
end
