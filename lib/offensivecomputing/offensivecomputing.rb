require 'net/http'
require 'openssl'

module OffensiveComputing
	
	class MalwareSearch
		@@baseurl = "http://www.offensivecomputing.net"
		@@user_agent = "Ruby/#{RUBY_VERSION} offensivecomputing rubygem (https://github.com/chrislee35/offensivecomputing)"

		attr_reader :cookie
		def initialize(username, password)
			# login and get a cookie
			# handle failures
			params = {'edit[name]' => username, 'edit[pass]' => password, 'edit[form_id]' => 'user_login_block'}
			@cookie = nil
			@referer = @@baseurl
			_post("?q=node&destination=node&op=Log+in", params)
		end
		
		def _request(request, url)
			request.add_field("User-Agent", @@user_agent)
			request.add_field("Referer", @referer)
			request.add_field("Cookie", @cookie) if @cookie

			http = Net::HTTP.new(url.host, url.port)
			if url.scheme == 'https'
				http.use_ssl = true
				http.verify_mode = OpenSSL::SSL::VERIFY_NONE
				http.verify_depth = 5
			end
			resp = http.request(request)
			@cookie = resp.header["set-cookie"].split(/[,; ]+/).find_all{|x| x=~ /PHPSESSID/}.last if resp.header["set-cookie"]
			resp.body
		end
		
		def _post(path, params=nil)
			url = URI.parse "#{@@baseurl}/#{path}"
			path = url.path
			if url.query
				path += "?"+url.query
			end
			#puts path
			request = Net::HTTP::Post.new(path)
			request.set_form_data(params) if params
			_request(request, url)
		end

		def _get(path, params=nil)
			url = URI.parse "#{@@baseurl}/#{path}"
			data = nil
			path = url.path
			if params and params.length > 0
				data = params.map { |k,v|
					"#{k}=#{v}".gsub(/([^ a-zA-Z0-9_.-=]+)/) do
						'%' + $1.unpack('H2' * $1.bytesize).join('%').upcase
					end.tr(' ', '+')
				}.join("&")
			end
			if data and url.query
				path += "?#{url.query}&#{data}"
			elsif data
				path += "?#{data}"
			elsif url.query
				path += "?#{url.query}"
			end
			request = Net::HTTP::Get.new(path)
			_request(request, url)
		end

		def search(hash)
			params = {'search'=>hash} # 'slowsearch'=>'on'
			body = _post('?q=ocsearch', params)
			records = []
			table = body.match(/<\!\-\- begin content.*?<\!\-\- end content \-\->/).to_s
			if table
				urls = table.scan(/download[^\"]+/)
				arr = table.gsub(/<.*?>/,"\t").gsub(/\s*\t+/,"\t").split(/\t/)
				#pp arr
				field = nil
				rec = {}
				avname = nil
				arr.each do |item|
					if item == "infected"
						records << MalwareResult.new(rec[:md5],rec[:sha1],rec[:sha256],rec[:filename],rec[:added],rec[:magic],rec[:packer],rec[:avresults],rec[:tags],rec[:dlurl], self)
					elsif item == "MD5:"
						field = :md5
					elsif item == "SHA1:"
						field = :sha1
					elsif item == "SHA256:"
						field = :sha256
					elsif item == "Original Submitted Filename:"
						field = :filename
					elsif item == "Date Added:"
						field = :added
					elsif item == "Magic File Type:"
						field = :magic
					elsif item == "Packer Signature:"
						field = :packer
					elsif item == "Anti-Virus Results:"
						field = :avresults
					elsif item == "Tags:"
						field = :tags
					elsif item == "Add a tag:"
						field = nil
					elsif item == "Download Sample"
						rec[:dlurl] = urls.shift
					elsif field == :md5 and item =~ /^[0-9a-f]{32}$/
						rec[field] = item
					elsif field == :sha1 and item =~ /^[0-9a-f]{40}$/
						rec[field] = item
					elsif field == :sha256 and item =~ /^[0-9a-f]{64}$/
						rec[field] = item
					elsif field == :filename
						rec[field] = item
					elsif field == :added and item =~ /^\d{4}\-\d{2}\-\d{2}/
						rec[field] = Time.parse("#{item} +0000").utc
					elsif field == :magic
						rec[field] = item
					elsif field == :avresults
						#puts "DEBUG: avresults #{item}"
						rec[field] = [] unless rec[field]
						if avname
							rec[field] << AVResult.new(avname,item)
							avname = nil
						else
							avname = item
						end
					elsif field == :tags
						rec[field] = [] unless rec[field]
						rec[field] << item
					end
				end
			end
			records
		end
		
		def download(malwareresult,filename=nil)
			if malwareresult.respond_to? :dlurl and malwareresult.dlurl
				doc = _get(malwareresult.dlurl)
				if filename
					File.open(filename,'w') do |f|
						f.write(doc)
					end
				end
				doc
			end
		end
	end
	
	class MalwareResult < Struct.new(:md5, :sha1, :sha256, :filename, :added, :magic, :packer, :avresults, :tags, :dlurl, :malwaresearch); 
		def download(filename=nil)
			self.malwaresearch.download(self,filename)
		end
	end
	class AVResult < Struct.new(:name, :signature); end
end
