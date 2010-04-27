#xiangwei 31531640@qq.com

require 'rubygems'
require 'optparse'
require 'jcode'
require 'iconv'  
require 'rchardet'
require 'ftools'

class String  
  def to_gbk(src_encoding='UTF-8')
    return self if src_encoding.upcase.strip=='GBK'
    Iconv.iconv("GBK//IGNORE","#{src_encoding}//IGNORE",self).to_s  
  end  
  def to_utf8(src_encoding='GBK')
    return self if src_encoding.upcase.strip=='UTF-8'
    Iconv.iconv("UTF-8//IGNORE","#{src_encoding}//IGNORE",self).to_s  
  end  
end 


exit if Object.const_defined?(:Ocra)

options = {}

optparse = OptionParser.new do|opts|
  # Set a banner, displayed at the top
  # of the help screen.
  opts.banner =<<'EOF'
批量转换txt文件为prc文档(Kindle使用）
1. 自动排版txt文件
2. 自动调整prc格式
3. 自动识别编码格式
使用方法:
  upig2prc [options] file_name"
EOF

  options[:temp] = '' 
  opts.on( '-t', '--temp output_name', '指定临时文件名') do |f|
    options[:temp] = f 
  end

  options[:output] = ''
  opts.on( '-o', '--output output_name', '指定输出文件名') do |f|
    options[:output] = f 
  end

  opts.on( '-h', '--help', '帮助' ) do
    puts opts
    exit
  end
end

optparse.parse!

keyword = ARGV.join(' ') 
options[:output] = File.basename(keyword, '.txt')+'.prc' if options[:output] == ''
options[:temp] = File.basename(keyword, '.txt')+'.html' if options[:temp] == ''

$stderr.puts optparse if keyword.strip==''

HTML_ESCAPE = { '&' => '&amp;',  '>' => '&gt;',   '<' => '&lt;', '"' => '&quot;',  ' '=>'&nbsp;' }

def h(s)
  s.to_s.gsub(/[&">< ]/) { |special| HTML_ESCAPE[special] }
end


script_path = File.expand_path(File.dirname(__FILE__))
html_header =<<"EOF"
<html><head><meta http-equiv="Content-Type" content="text/html; charset=utf-8"><link REL="stylesheet" TYPE="text/css" HREF="xiang.css"></head><body topmargin="0" leftmargin="0" bottommargin="0" rightmargin="0">
EOF
html_footer =<<'EOF'
</body></html>
EOF
html_header = html_header.to_utf8
html_footer = html_footer.to_utf8

keyword.strip!
File.open(options[:temp], 'w'){|temp_file|
  File.open(keyword, 'r'){|f|
    src_str = f.read
    encode_det = CharDet.detect(src_str[0..100])
    encoding = encode_det['encoding'].upcase
    confidence = encode_det['confidence']
    $stderr.puts '编码不能正确识别' if confidence <0.1
    puts 'begin'

    temp_file.print html_header

    src_str_utf8 = src_str.to_utf8(encoding)
    src_str_utf8.each_line {|line|
      line.gsub!('　'.to_utf8, '  '.to_utf8)
      line.lstrip!
      #todo escape html code
      temp_file.print '<p>'+h(line)+'</p>'
    }

    temp_file.print html_footer

    puts 'end'
  }
}

if File.exist?('xiang.css') && !File.exist?('upig2prc.exe')
  $stderr.puts 'txt目录下不能有xiang.css'
  exit 
end

`pause`
File.copy((File.join(script_path, '../bin/temp/xiang.css')), 'xiang.css')
result = `temp/kindlegen.exe "#{options[:temp]}"`
$stderr.puts result if result.include?('Error')
File.delete(options[:temp])

if File.exist?('xiang.css') && !File.exist?('upig2prc.exe')
  File.delete('xiang.css')
end

