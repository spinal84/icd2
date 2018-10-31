####################################################################
# Transform the collection of strings to doxygen comment that will #
# be inserted to the source file. There are different handling for #
# different types of comments.                                     #
####################################################################

# For all types
# (1)
#/** line1 */

# Functions
# (2)
#/**
# * line1
# * @param  ...
# * @return ...
# * @todo   ...
# */

# (3)
#/**
# * line1
# * line2
# * line3
# *
# * @param  ...
# * @return ...
# * @todo   ...
# */

# (4)
#/**
# * line1
# *
# * @param  ...
# * @param  ...
# *
# * @return ...
# * @note   ...
# * @todo   ...
# */

# Enum, Struct, Variable, Typedef, Define
# (5)
#/** line1
# * line2
# * line3 */

# (6)
#/** line1
# *
# * line2
# * line3
# */

# (7)
#/** line1
# * @...
# */

# (8)
#/** line1
# * line2
# *
# * @...
# */

class String
	def wrap(length)
		gsub(/(.{1,#{length}})(\s+|\Z)/, "\\1\n")
	end

	def wrap!(length)
		gsub!(/(.{1,#{length}})(\s+|\Z)/, "\\1\n")
	end
end

class StringComment
	@@wrap = WRAP

	def initialize(type = :none)
		@type = type
		@strings = []
	end

	def <<(str)
		@strings << str.gsub(/ /, ' ').strip
	end

	# The comments "(num)" are the references to the comments styles
	# described above in the header of this file
	def to_s
		return nil if @strings.empty?

		# (1)
		if @strings.size == 1 and indent + @strings[0].size + 3 < @@wrap
			return ' ' * indent + "/** #{@strings[0]} */"
		end

		prefix = ''
		first_line = true
		params_flag = false

		# (2), (3), (4)
		if @type == :Function
			result = "/**\n"

			@strings.each do |s|
				if s[0] == '@'
					if need_newline? and !params_flag and s == '@param'
						result << " *\n"
						params_flag = true
					end

					if params_flag and s != '@param'
						params_flag = false
						result << " *\n" if need_newline?
					end

					prefix = s
					next
				end

				prefix = "%-#{entity_len}s" % prefix if not prefix.empty?
				if s.is_a?(Array)
					raise if prefix[0, 6] != '@param'
					prefix += "%-#{param_len}s" % s[0]
					s = s[1]
				end
				result << wrap(s, prefix)

				# We force the new line if description is multiline
				if first_line
					first_line = false
					result << " *\n" if result.lines.size > 2 and not need_newline?
				end

				prefix = ''
			end

			return result + " */"
		end

		# Enum, Struct, Variable, Typedef, Define
		@strings.each do |s|
			if s[0] == '@'
				if not params_flag
					# We force the new line if description is multiline (8)
					result << ' ' * indent + " *\n" if result.lines.size > 1
					params_flag = true  # (7)
				end
				prefix = s
				next
			end

			prefix = "%-#{entity_len}s" % prefix if not prefix.empty?

			if s.is_a?(Array)
				raise if prefix[0, 6] != '@param'
				prefix += "%-#{param_len}s" % s[0]
				s = s[1]
			end

			if first_line
				# We need extra char on the first line for proper wrapping
				result = wrap('!' + s, prefix)
				# Remove extra char
				result.sub!(/!/, '')
				first_line = false
			else
				result << wrap(s, prefix)
			end
			prefix = ''
		end

		params_flag = (result =~ /^#{' ' * indent + ' \*$'}/) if not params_flag  # (6)

		result[indent, 1] = '/*'
		if params_flag  # (6), (7), (8)
			result << ' ' * indent + ' */'
		else  # (5)
			result = result.rstrip + ' */'
		end
	end

	private
	def indent
		return @indent if @indent
		if @type == :'Enumeration Member' or @type == :'Member Data'
			@indent = 2
		else
			@indent = 0
		end
	end

	def asterix
		@type != :none
	end

	# Function comment helper
	# (7), (8), (9)
	def need_newline?
		params_total > 1
	end

	# Count of '@param' entities
	def params_total
		return @params_total if @params_total
		@params_total = @strings.select{|s| s == '@param'}.size
	end

	# Find maximum entity ("@return", "@param"...) length
	def entity_len
		return @entity_len if @entity_len
		@entity_len = @strings.select{|s| s[0] == '@'}.map{|s| s.size}.max + 1 rescue 0
	end

	# Maximum length of parameters name
	def param_len
		return @param_len if @param_len
		@param_len = @strings.select{|s| s.is_a? Array}.map{|p| p[0].size}.max + 2
	end

	def wrap(string, prefix = '')
		string = string.gsub(/@ref /, '@ref_')

		if prefix == ''
			ary = string.split(/(?=<pre>)|(?<=<\/pre>)/)
			if asterix
				ary = ary.map do |s|
					next s if s =~ /^<pre>/
					s.wrap(@@wrap - 3 - indent).lines.map{|l| ' '+ l}.join
				end
				string = ary.join.gsub(/\s*<p>\s*/, "\n\n ").gsub(/<\/pre> +/, "</pre>\n ").
					lines.map{|s| ' ' * indent + " *" + s.sub(/\s*$/, "\n")}.join
			else
				ary.each do |s|
					s.wrap!(@@wrap) if s !~ /^<pre>/
				end
				string = ary.join.gsub(/\s*<p>\s*/, "\n\n").gsub(/<\/pre> +/, "</pre>\n").
					lines.map{|s| s.sub(/\s*$/, "\n")}.join
			end
		else  # prefix != ''
			if asterix
				string = string.wrap(@@wrap - 3 - indent - prefix.length).lines.
					map{|l| ' ' * indent + ' * ' + ' ' * prefix.length + l}.join
				string[3 + indent, prefix.length] = prefix
			else  # no asterix means no indentation as well
				string = string.wrap(@@wrap - prefix.length).lines.
					map{|l| ' ' * prefix.length + l}.join
				string[0, prefix.length] = prefix
			end
		end

		string.gsub(/@ref_/, '@ref ')
	end
end
