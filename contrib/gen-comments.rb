#!/usr/bin/ruby
###########################################################
# Extract comments from html files and put to the sources #
###########################################################
require 'nokogiri'
require 'strscan'
require 'set'

INTERACTIVE=false
WRAP=77

$:.unshift(File.dirname(__FILE__))
require 'string_comment'

# Expand Nokogiri for parsing doxygen generated HTML
module Nokogiri::XML::Searchable
    @@struct = Dir[File.dirname(__FILE__) + '/legacy/struct*.html'].grep_v(/-members\.html$/).
	map{|fn| fn.sub(/^.*\/struct/, '').sub(/\.html/, '').gsub(/__/, '_').to_sym}.to_set

    # Change links text from "link" to "#link"
    # It's needed for doxygen formatting
    def fix_links
	css('a').each do |link_node|
	    child = link_node.child
	    if child.is_a? Nokogiri::XML::Text
		link_text = child.text
		next if link_text == 'Todo:'
		if link_node[:href] =~ /^group__(.+)\.html$/
		    link_text = "@ref " + $1.sub(/\.html$/, '').gsub(/_+/, '_')
		elsif link_node[:href] =~ /\//
		    if link_node[:href] == link_text
			link_node.replace(Nokogiri::XML::Text.new(link_text, child.document))
		    end
		    next
		elsif ( ! @@struct.member?(link_text.to_sym) and
			! CommentsHandler.src_files[link_text.to_sym] and
			link_text !~ /^\w+\(\)$/ )
		    # Exclude functions, struct and filenames
		    link_text = '#' + link_text
		end
		link_node.replace(Nokogiri::XML::Text.new("#{link_text}", child.document))
	    end
	end
	self
    end
end

class Nokogiri::XML::NodeSet
    # Run this after fix_links
    def remove_refs
	pop while last.text =~ /\A\s+\z/
	if last.name == 'p' and last.child.text =~ /^(Referenced by|References) /
	    pop
	    remove_refs #run again
	end
	self
    rescue
	self
    end
end

class Nokogiri::XML::Node
    # Get the list of "Todo:" and unlink found nodes
    # Multiple "Todo:" is possible, so we return Array here
    # See icd_request_try_iap_cb() for example
    def todo_list
	return @todo_list if @todo_list
	@todo_list = Array.new
	css('.memdoc dt').select{|n| n.text == 'Todo:'}.each do |todo_node|
	    todo_node = todo_node.next
	    @todo_list << todo_node.text.gsub(/[ \s]+/, ' ').strip
	    todo_node.parent.unlink
	end
	# Fix wrong parsing if the first entity in description was "Todo:"
	# See icd_network_api_foreach_module() API docs for example
	desc_child = css('.memdoc')[0].children[1]
	desc_child.unlink if desc_child.name == 'p' and desc_child.text == "\n"
	@todo_list
    end

    # Return "Note:" text and unlink the found node
    def note
	note_node = css('.memdoc dt').find{|n| n.text == 'Note:'}
	return nil if note_node.nil?
	note_node = note_node.next
	note_text = note_node.text.gsub(/[ \s]+/, ' ').strip
	note_node.parent.unlink
	note_text
    end
end

# Single comment extracted from HTML
class Comment
    attr_reader :type
    # node - Nokogiri::XML::Node
    # type - documentation type
    def initialize(node, type)
	@node, @type = node, type
	@node.css('.memdoc').fix_links
	# Sometimes typedefs are declared as variables in doxygen API docs
	# Example: enum icd_policy_status(* icd_policy_nw_connect_fn) ...
	if type == :Variable and head =~ /\(.+\)\s*\(.+\)/
	    @type = :Typedef
	    @head = "typedef #@head"
	end
    end

    # Source code file name extracted from doxytag
    def file
	return @file if @file
	doxytag =~ /doxytag: member="(.+)::/
	@file = $1
    end

    # Head extracted from HTML.
    # Needed for searching in the source code.
    def head
	return @head if @head
	prefix = ''
	@node.css('.memproto tr code').each do |element|
	    prefix = 'static ' if element.text.strip == '[static]'
	    element.unlink
	end
	@head = (prefix + @node.css('.memproto td')[0].text.gsub(/[ \s]+/, ' ')).
	    strip.sub(/^(static\s+)+/, 'static ') + (type == :Function ? '()' : '')
    end

    # doxytag comment content:
    # <!-- doxytag: ... -->
    def doxytag
	return @doxytag if @doxytag
	if @node.previous.previous.comment?
	    @doxytag = @node.previous.previous.text
	elsif @node.previous.children[-2].comment?
	    @doxytag = @node.previous.children[-2].text
	end
    end

    # Regex to search in source code
    def regex
	return @regex if @regex
	string = head.dup
	string.sub!(/\(\)/, '') if type == :Function
	string = string.gsub(/\s*([.*()\[\]])\s*/, '\s*\\\\\1\s*').
	    gsub(/\s*(,)\s*/, '\s*\1\s*').gsub(/\s+/, '\s+')

	if type == :Variable
	    string = '(const\s+)?' + string if string !~ /^(static|const)\\s\+/
	end

	if type == :Function or type == :Variable
	    string = '(static\s+)?' + string if string !~ /^static\\s\+/
	end

	if type == :Function
	    string = '(inline\s+)?' + string + '\s*\([^\)]*\)\s*\{'
	elsif type == :'Enumeration Type'
	    string += '\s*\{'
	end

	@regex = Regexp.new('^' + string.gsub(/(\\s\*)+/, '\s*'))
    end

    # Return start_pos of found declaration
    # Raise error if more than 1 declaration found
    # Arguments:
    # ss - StringScanner
    def declaration_pos(ss)
	result = []
	while ss.skip_until(regex)
	    result << ss.charpos - ss.matched_size
	end
	ss.reset
	if result.size > 1
	    puts "\n*** Multiple declarations detected, please fix and rerun."
	    puts "*** Press Enter to continue."
	    # TODO: INTERACTIVE
	    $stdin.gets
	    raise
	end
	result[0]
    end

    # The text of comment to insert in the source code
    # nil if empty comment parsed
    def text
	return @text if @text

	sc = StringComment.new(type)
	todo_list = @node.todo_list
	note = @node.note

	# Run to unlink nodes
	params()
	returns()
	children()
	values_unlink()

	sc << details if details
	params.each{|p| sc << '@param' << p}
	sc << '@return' << returns if returns
	sc << '@note' << note if note
	todo_list.each{|todo| sc << '@todo' << todo}

	# Sanity check
	params_node = @node.css('.memdoc dt').find{|n| n.text == 'Parameters:'}
	return_node = @node.css('.memdoc dt').find{|n| n.text == 'Returns:'}
	if params_node || return_node || @node.note
	    puts "\n*** Duplicated or corrupted section found! Please fix HTML and try again."
	    puts "*** Press Enter to continue."
	    # TODO add INTERACTIVE flag
	    $stdin.gets
	    raise
	end

	@text = sc.to_s
    end
    alias :to_s :text

    def details
	return @details if @details
	@details = @node.css('.memdoc')[0].children[1..-1].remove_refs.to_html.
	    sub(/^\s*<p>\s*/, '').gsub(/<\/(p|li)>/, '').gsub(/(<li>)\s*/, '\1')
	@details = nil if @details.empty?
	@details
    rescue
	nil
    end

    # Child comments for enum and struct
    def children
	return @children if @children
	enum_node = @node.css('.memdoc dt').find{|n| n.text == 'Enumerator: '}
	return @children = [] if enum_node.nil?
	enum_node = enum_node.parent
	@children = enum_node.css('tr').map{|r| EnumComment.new(r, self)}
	enum_node.unlink
	@children
    end

    private
    def params
	return @params if @params
	params_node = @node.css('.memdoc dt').find{|n| n.text == 'Parameters:'}
	return @params = [] if params_node.nil?

	params_node = params_node.next
	@params = params_node.css('tr').map do |r|
	    [ r.css('td')[1].text.gsub(/[ \s]+/, ' ').strip,
	      r.css('td')[2].text.gsub(/[ \s]+/, ' ').strip ]
	end
	params_node.parent.unlink

	@params
    end

    def returns
	return @returns if @returns
	return_node = @node.css('.memdoc dt').find{|n| n.text == 'Returns:'}
	return nil if return_node.nil?
	return_node = return_node.next
	@returns = return_node.text.gsub(/[ \s]+/, ' ').strip
	return_node.parent.unlink
	@returns
    end

    def values_unlink
	values = @node.css('.memdoc b').select do |n|
	    n.text == 'Initial value:' or n.text == 'Value:'
	end
	values.each do |node|
	    node.parent.next.unlink
	    node.parent.unlink
	end
    end
end

# Single Enumerator member comment extracted from HTML
class EnumComment < Comment
    # node - Nokogiri::XML::Node <tr>
    def initialize(node, parent)
	@member  = node.css('td')[0].text.gsub(/[ \s]+/, ' ').strip
	@comment = node.css('td')[1].text.gsub(/[ \s]+/, ' ').strip
	@parent  = parent
    end

    # We assume double space indentation
    def regex
	return @regex if @regex
	@regex = /^  #@member\b/
    end

    # Return start_pos of found declaration
    # Raise error if more than 1 declaration found
    # Arguments:
    # ss - StringScanner
    def declaration_pos(ss)
	result = []
	start_pos = ss.pos = ss.string[0, @parent.declaration_pos(ss)].bytesize
	ss.skip_until(/}/)
	end_pos = ss.charpos + 1
	ss.pos = start_pos
	while ss.skip_until(regex)
	    result << ss.charpos - ss.matched_size if ss.charpos < end_pos
	end
	ss.reset
	if result.size > 1
	    puts "\n*** Multiple declarations detected, please fix and rerun."
	    puts "*** Press Enter to continue."
	    # TODO: INTERACTIVE
	    $stdin.gets
	    raise
	end
	result[0]
    end

    # Assume double space indentation
    def text
	return @text if @text
	sc = StringComment.new(type)
	sc << @comment
	@text = sc.to_s
    end
    alias :to_s :text

    def type
	:'Enumeration Member'
    end

    def head
	"#{@parent.head} { #@member ... };"
    end

    def file
	@parent.file
    end
end

# Doxy has separate file for each struct description
# This class is a comment for a whole struct, extracted from HTML
class StructComment < Comment
    # page - nokogiri parsed page
    def initialize(page)
	@page = page
    end

    def head
	"struct #{name}"
    end

    def regex
	return @regex if @regex
	@regex = /^struct\s+#{name}\s*{/
    end

    def text
	return @text if @text
	sc = StringComment.new(type)
	sc << details
	@text = sc.to_s
    end
    alias :to_s :text

    def file
	return @file if @file
	@file = File.basename(@page.css('hr')[-2].next.next.text.strip)
    end

    def children
	return @children if @children
	@children = @page.css('.memitem').map{|node| StructMemberComment.new(node, self)}
    end

    def type
	:Struct
    end

    private
    def name
	return @name if @name
	@name = @page.css('h1').first.child.text.sub(/ Struct Reference$/, '')
    end

    def details
	return @details if @details
	details_nodes = @page.css('[name=_details]')
	details_nodes << details_nodes.last.next while details_nodes.last.next.name != 'hr'
	details_nodes.fix_links
	@details = @page.css('[name=_details]')[0].next.next.text.gsub(/[ \s]+/, ' ').strip
    end
end

# Single struct member comment extracted from HTML
class StructMemberComment < EnumComment
    # node - Nokogiri::XML::Node <tr>
    def initialize(node, parent)
	@node, @parent = node, parent
	comment()
	member()
    end

    def text
	return super if @todo_list.empty? and @node.nil?

	sc = StringComment.new(type)
	sc << @comment
	sc << '@note' << @note if @note
	@todo_list.each{|todo| sc << '@todo' << todo}
	@text = sc.to_s
    end
    alias :to_s :text

    def type
	:'Member Data'
    end

    def head
	return @head if @head
	@head = @node.css('.memproto tr .memname').text.gsub(/[ \s]+|\[.*\]/, ' ').strip
    end

    private
    def member
	return @member if @member
	@member = head.sub(/\S*::/, '').gsub(/\s*\*\s*/, '\s*\*\s*').gsub(/ /, '\s+')
    end

    def comment
	return @comment if @comment
	@todo_list = @node.todo_list
	@note = @node.note
	# For @params example check struct member gint icd_osso_ic_stats_data::dB
	params_node = @node.css('.memdoc dt').find{|n| n.text == 'Parameters:'}
	if params_node
	    # Params node should be fixed by the user
	    puts "\nSanity check failed for '#{head}'\nPlease fix and run again. Hit Enter..."
	    $stdin.gets
	    raise
	end
	@comment = @node.css('.memdoc').fix_links[0].children[1].text.strip
    end
end

# Head comment for the file class
class HeadComment
    # file - path to html file
    # page - nokogiri parsed page
    def initialize(file, page)
	@file, @page = file, page
	@filename = File.basename(file)
    end

    # @long is the file selected for full group description
    attr_writer :long

    # file - source code file where we want the head comment to be put
    # long - do we want full group description in the head comment?
    def comment(file = nil)
	if file_reference?
	    @comment = "/**\n"
	    @comment << file_desc.strip << "\n */"
	else
	    return nil if group.nil?
	    @comment = "/**\n"
	    if file
		desc = file_desc(file)
		@comment << "#{desc}".strip << "\n\n" if desc
	    end
	    @comment << "@addtogroup #{group} #{group_title}" if group
	    @comment << "\n\n" + wrap_pre(group_details).strip if @long == file and group_details
	    @comment << "\n\n@ingroup #{parent_group}" if parent_group
	    @comment << "\n\n * @{ */" if group
	end
    rescue
	@comment = nil
    end

    # @group extracted from HTML
    def group
	return @group if @group
	@group = get_group(@filename)
    end

    # ...
    def group_title
	return @group_title if @group_title
	node = @page.css('h1')[0]
	addr_node = node.css('a').any? ? node.css('a')[0] : nil
	@parent_group = get_group(addr_node[:href]) if addr_node
	@group_title = node.text.lines[0].strip
    rescue
	nil
    end

    # The description of the @group
    def group_details
	return @group_details if @group_details
	details = @page.css('[name=_details]')
	details << details.last.next while details.last.next.name != 'hr'
	details.fix_links
	details = @page.css('[name=_details]')
	details << details.last.next while details.last.next.name != 'hr'
	2.times{details.shift}
	@group_details = details.to_html.gsub(/<\/(p|li)>/, '').gsub(/(<li>)\s*/, '\1')
	@group_details = nil if @group_details.empty?
	@group_details
    rescue
	nil
    end

    # @ingroup extracted from HTML
    def parent_group
	return @parent_group if @parent_group
	group_title
	@parent_group
    end

    # "@file" doxygen description extracted from HTML
    # Arguments:
    # file - source code file name, not needed if @page is a File Reference
    def file_desc(file = nil)
	if file_reference?
	    page = @page
	else
	    file_doxy = File.dirname(@file) + '/' + File.basename(file).gsub(/_/, '__').gsub(/\./, '_8') + ".html"
	    page = Nokogiri::HTML.parse(File.open file_doxy)
	end
	file = File.basename(page.css('h1').first.child.text.sub(/ File Reference/, ''))
	desc = page.css('[name=_details]')[0].next.next.text.gsub(/[ \s]+/, ' ').strip
	if desc =~ /^copyright\s/i
	    copyright = "#{wrap(desc.sub(/^copyright\s+/i, ''))}"
	    desc = "@file #{file}"
	elsif "@file #{file} #{desc}".length > WRAP
	    desc_wrapped = wrap(desc).strip
	    newlines = desc_wrapped.lines.size > 1 ? "\n\n" : "\n"
	    desc = "@file #{file}" + newlines + desc_wrapped
	elsif !desc.empty?
	    desc = "@file #{file} #{desc}"
	else
	    desc = "@file #{file}"
	end
	# Authors parsing
	authors = page.css('.author dd').map{|a| a.text.gsub(/[  \t]+/, ' ').strip.lines}.flatten
	authors = authors.map{|a| a.strip}.uniq
	if authors.any?
	    if authors.size > 1
		desc << "\n\n@authors " << authors.join("\n	 ")
	    else
		desc << "\n\n@author " + authors[0]
	    end
	end
	desc << "\n\n@copyright #{copyright}" if copyright
	desc
    rescue
	nil
    end

    private
    def get_group(file)
	return nil if file !~ /^group_/
	file.gsub(/_+/, '_').gsub(/^group_|\..*$/, '')
    end

    def file_reference?
	@page.title =~ / File Reference$/
    end

    def wrap(string)
	string = string.gsub(/@ref /, '@ref_')
	string.gsub!(/(.{1,#{WRAP}})(\s+|\Z)/, "\\1\n").strip
	string.gsub(/@ref_/, '@ref ')
    end

    # Wrap with <pre> tags
    def wrap_pre(string)
	string = string.gsub(/@ref /, '@ref_')
	ary = string.split(/(?=<pre>)|(?<=<\/pre>)/)
	ary.each do |s|
	    s.gsub!(/(.{1,#{WRAP}})(\s+|\Z)/, "\\1\n") if s !~ /^<pre>/
	end
	ary.join.gsub(/\s*<p>\s*/, "\n\n").gsub(/<\/pre> +/, "</pre>\n").
	    lines.map{|s| s.sub(/\s*$/, "\n")}.join.gsub(/@ref_/, '@ref ')
    end
end

# Collection of the comments extracted from HTML file
class DoxyComments
    # page - nokogiri parsed page
    def initialize(page)
	@page = page
	lines_structure()
	if struct?
	    @comments = [ StructComment.new(page) ]
	else
	    @comments = page.css('.memitem').map{|node| Comment.new(node, type(node))}
	end
    end

    include Enumerable
    def each
	@comments.each do |comment|
	    yield comment
	    comment.children.each do |child|
		yield child
	    end
	end
    end

    def [](index)
	@comments[index]
    end

    def size
	return @size if @size
	@size = @comments.inject(0){|sum, comment| sum + 1 + comment.children.size}
    end

    def struct?
	@page.title =~ / Struct Reference$/
    end

    private
    # Get the structure of the document
    # It's the array of line numbers starting types of declaration in HTML
    # 2 groups of possible declarations include:
    #  - Define, Function, Typedef, Variable
    #  - Enumeration Type, Member Data (struct)
    def lines_structure
	# Structure contains: [line_number, doc_type]
	return @lines_structure if @lines_structure
	@lines_structure = Array.new
	@page.css('h2').each do |node|
	    next if node.text !~ / Documentation$/
	    @lines_structure << [node.line, node.text.sub(/ Documentation$/, '').to_sym]
	end
    end

    def type(node)
	res = nil
	lines_structure.each do |line, name|
	    if node.line > line
		res = name
	    else
		break
	    end
	end
	res
    end
end

# Source file handler: change/add comments
class SourceFile
    attr_reader :path
    alias :to_s :path
    def initialize(path)
	@path = path
    end

    # Clear caches stored in class instance after changing the content
    def clear_cache
	@all_comments, @head_index, @ss = nil
	$changed = @changed = true
    end

    # Source file content
    def content
	return @content if @content
	@content = File.read(@path)
    end

    # Just a StringScanner instance for working with file content
    def ss
	return @ss if @ss
	@ss = StringScanner.new(content)
    end

    # Array of doxy comments found in source file
    # Holds char positions of the comments (ranges)
    def all_comments
	return @all_comments if @all_comments
	@all_comments = []
	while ss.skip_until(/^ *\/\*\*/)
	    start = ss.charpos - ss.matched_size
	    ss.skip_until(/\*\//)
	    fin = ss.charpos - 1
	    @all_comments << (start..fin)
	end
	ss.reset
	@all_comments
    end

    # Return doxy comment content
    def [](index)
	content[all_comments[index]] rescue nil
    end

    include Enumerable
    def each
	all_comments.each {|r| yield content[r]}
    end

    # Get head comment
    def head_comment
	self[head_index]
    end

    # Set head comment or change its contents
    def head_comment=(c)
	head_comment_prep(c)
	content[all_comments[head_index]] = c
	clear_cache
    end

    # Return comment that is found in the file
    def doxy_comment(c)
	range = find_range(c)
	content[range] if range
    end

    # Add or replace comment
    def add_comment(c)
	range = find_range(c)
	if range
	    content[range] = c.text
	else
	    content.insert(c.declaration_pos(ss), c.text + "\n")
	end
	clear_cache
    end

    def changed?
	@changed
    end

    # Write changes to the file
    def write!
	# Make a backup
	#File.rename(@path, @path + '.bak')
	File.write(@path, content)
	@changed = false
    end

    private
    # Return range of the comment in the source file
    def find_range(c)
	pos = c.declaration_pos(ss) - 2
	all_comments.find{|r| r.include?(pos)}
    rescue
	nil
    end

    # If there's no head comment in the file, we add a template
    def head_comment_prep(c)
	return if head_index
	curly_braces = (c =~ /@{/)
	if @path =~ /\.h(\.in)?$/
	    # /** @{ */
	    define_regex_str = '^(#define ' + File.basename(@path, '.*').upcase.gsub(/[-.]/, '_') + '(?:_H)?)$\s+'
	    regex = Regexp.new(define_regex_str)
	    content.sub!(regex, "\\1\n\n/** @{ */\n\n")
	    # /** @} */
	    if curly_braces
		start_pos = end_pos = content.rindex /^#endif\b/
		start_pos -= 1 while content[start_pos - 1] =~ /\s/
		content[start_pos...end_pos] = "\n\n/** @} */\n\n"
	    end
	else  # *.c
	    content.insert(0, "/** @{ */\n\n")
	    content.insert(-1, "\n/** @} */\n") if curly_braces
	end
	clear_cache
    end

    # Index of the head comment or nil
    def head_index
	return @head_index if @head_index
	@head_index = find_index {|c| c =~ /@file /}
	@head_index = @head_index || find_index {|c| c =~ /@{/}
    end
end

# Extract comments from HTML files and inject to the sources
class CommentsHandler
    @@src_files = []
    @@extracted = 0
    @@injected  = 0
    @@replaced   = 0
    @@failed    = 0
    @@same      = 0

    def initialize(html_file)
	@html_file = html_file
	src_files
    end

    def run
	@engaged_files = Set.new
	@comments_failed = []

	# Extracting comments
	puts ">>> Processing file: #@html_file ..."
	@page = Nokogiri::HTML.parse(File.open @html_file)
	@head_comment = HeadComment.new(@html_file, @page)
	@comments = DoxyComments.new @page

	# Loop on extracted comments
	@comments.each_with_index do |c, i|
	    @@extracted += 1

	    src = src_files[c.file.to_sym]
	    if src.nil?
		puts "Skipping: file not found '#{c.file}'"
		@comments_failed << c
		next
	    else
		@engaged_files << src
	    end

	    src_comment = src.doxy_comment(c)
	    puts "\n#{c.type}: #{c.head}\nFile: #{src}"

	    if src_comment
		if src_comment == c.to_s
		    puts "Skipping: same as parsed."
		    @@same += 1
		else
		    puts "\nComment from the source:\n#{src_comment}\n\nComment parsed from HTML:\n#{c}"
		    print "\n  [#{i+1}/#{@comments.size}] Replace?"
		    read_yn and src.add_comment(c)
		    @@replaced += 1
		end
	    else
		begin
		    if c.text
			src.add_comment(c)
			puts "\nComment parsed from HTML:\n#{c}"
			@@injected += 1
		    else
			# No comment found in the source and empty comment was parsed from HTML
			puts "Skipping: same as parsed."
			@@same += 1
		    end
		rescue
		    puts "Skipping: adding failed"
		    @comments_failed << c
		    @@failed += 1
		end
	    end
	end

	# Head comments loop.
	# Several files may be affected after extracting head comment from HTML
	if not @comments.struct?
	    # If there are several files affected, we want full group description
	    # to go only to one file (priorities: .h.in, .h, .c, other)
	    long_comment = @engaged_files.find{|f| f.path =~ /\.h\.in$/}
	    long_comment = long_comment || @engaged_files.find{|f| f.path =~ /\.h$/}
	    long_comment = long_comment || @engaged_files.find{|f| f.path =~ /\.c$/}
	    long_comment = long_comment || @engaged_files.find{|f| true}
	    @head_comment.long = long_comment.path if long_comment
	    @engaged_files.each do |f|
		next  ## SKIP adding new comments
		puts "\nHead comment for #{f.path}"
		@@extracted += 1
		if f.head_comment
		    if f.head_comment == @head_comment.comment(f.path)
			puts "Skipping: same as parsed."
			@@same += 1
		    else
			puts "\nHead comment from the source:\n#{f.head_comment}\n\n" +
			    "Head comment parsed from HTML:\n#{@head_comment.comment(f.path)}"
			print "\n  Replace?"
			if read_yn
			   f.head_comment = @head_comment.comment(f.path)
			    @@replaced += 1
			end
		    end
		else
		    puts "\nHead comment parsed from HTML:\n#{@head_comment.comment(f.path)}"
		    f.head_comment = @head_comment.comment(f.path)
		    @@injected += 1
		end
	    end
	end
    end

    def self.write!
	# Write changes to source files
	if $changed
	    puts
	    @@src_files.each_value do |f|
		next unless f.changed?
		puts "File: #{f} changed, writing..."
		f.write!
	    end
	    puts
	end

	$changed = false
    end

    def missing_entities
	# Inform the user if there was a trouble adding extracted comments
	if @comments_failed.any?
	    puts "\n" + "-" * WRAP + "\n>>> Following entities have failed adding comments.\n    Are they missing in the source tree?"
	    current_file = nil
	    @comments_failed.each do |c|
		file = src_files[c.file.to_sym]
		if current_file != file or file.nil?
		    if file.nil?
			puts "File not found: '#{c.file}'" if current_file != c.file
			current_file = c.file
		    else
			puts "\nFile: #{file.to_s.sub(/^.*\/(icd2\/)/, '')}"
			current_file = file
		    end
		end
		puts "  #{c.type}: #{c.head}"
	    end
	    puts "\nCheck above message and press Enter..."
	    $stdin.gets if INTERACTIVE
	end
    end

    def self.show_stats
	out = "Total: %d" % @@extracted
	out << ", added: %d" % @@injected if @@injected > 0
	out << ", replaced: %d" % @@replaced if @@replaced > 0
	out << ", failed: %d" % @@failed if @@failed > 0
	out << ", same: %d" % @@same if @@same > 0
	print out + "\n" if @@extracted > 0
    end

    private
    # files is hash of pairs { :file_name => SourceFile instance }
    def src_files
	return @@src_files if @@src_files.any?
	prj_dir = File.expand_path(@html_file).sub(/(\/icd2\/).*$/, "$1")
	files = `find #{prj_dir} -type f -name '*.h' -or -name '*.h.in' -or -name '*.c'`.lines.map{|f| f.strip}
	@@src_files = files.map{|f| [f.sub(/^.*\//, '').to_sym, SourceFile.new(f)]}.to_h
    end

    # Ask user yes/no question
    def read_yn
	print " (Y/n) "
	res = INTERACTIVE ? $stdin.gets !~ /^n/i : true
	puts "  User said '" + (res ? 'Yes' : 'No') + "'."
	res
    end

    def CommentsHandler.src_files
	@@src_files
    end
end

############
# The code #
############

path = File.expand_path(ARGV[0]) rescue File.dirname(__FILE__) + '/legacy'

if File.directory? path
    files = Dir["#{path}/*.html"]
else
    files = [path]
end

files.each do |file|
    handler = CommentsHandler.new(file)
    handler.run
    handler.missing_entities
end

CommentsHandler.write!
CommentsHandler.show_stats

# vim:ts=8:sts=4:sw=4:noet
