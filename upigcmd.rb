#xiangwei 31531640@qq.com

require 'rubygems'
require 'optparse'
require 'jcode'
require 'iconv'  
require 'rchardet'
require 'ftools'

exit if Object.const_defined?(:Ocra)

class String  
  def to_gbk(src_encoding='UTF-8')
    return self if src_encoding.upcase.strip=='GBK'
    Iconv.iconv("GBK//IGNORE","#{src_encoding}//IGNORE",self).to_s  
  end  
  def to_utf8(src_encoding='GBK')
    return self if src_encoding.upcase.strip=='UTF-8'
    src_encoding = 'GBK' if src_encoding.upcase.strip =='GB2312'
    Iconv.iconv("UTF-8//IGNORE","#{src_encoding}//IGNORE",self).to_s  
  end  
end 


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
  options[:output] = ''
  opts.on( '-o', '--output output_name', '指定输出文件名(只用到了路径)') do |f|
    options[:output] = f 
  end

  opts.on( '-h', '--help', '帮助' ) do
    puts opts
    exit
  end
end


optparse.parse!

if options[:output]=='' 
  output_path = '.'
else
  output_path = File.dirname(options[:output])
end

orign_input_file = ARGV.join(' ') 
orign_input_file.strip!

file_title = File.basename(orign_input_file, File.extname(orign_input_file))
file_type = File.extname(orign_input_file)

script_path = File.expand_path(File.dirname(__FILE__))
origin_path_css = File.join(script_path, '../bin/temp/xiang.css')

output_bare_file_name = file_title+'.prc'
output_path_css = File.join(output_path, 'xiang.css')
output_path_prc = File.join(output_path, output_bare_file_name)

input_file_name = ''
if file_type=~/(html|epub|htm)/i
  input_file_name = File.join(output_path, file_title+file_type)
elsif file_type=~/txt/i 
  input_file_name = File.join(output_path, file_title +'.html')
else
  $stderr.puts "Wrong File Type: #{file_type}"
  $stderr.puts optparse
  `pause`
  exit 
end
puts input_file_name
no_css_in_dir = true
no_input_file_name = true
if File.exist?(output_path_css)
  no_css_in_dir = false
end
if File.exist?(input_file_name)
  no_input_file_name = false
end

File.copy(orign_input_file, input_file_name) if no_input_file_name && file_type=~/(html|epub|htm)/i 
File.copy(origin_path_css, output_path_css) if no_css_in_dir

HTML_ESCAPE = { '&' => '&amp;',  '>' => '&gt;',   '<' => '&lt;', '"' => '&quot;',  ' '=>'&nbsp;' }

def h(s)
  s.to_s.gsub(/[&">< ]/) { |special| HTML_ESCAPE[special] }
end


html_header =<<"EOF"
<html><head><meta http-equiv="Content-Type" content="text/html; charset=utf-8"><link REL="stylesheet" TYPE="text/css" HREF="xiang.css"></head><body topmargin="0" leftmargin="0" bottommargin="0" rightmargin="0">
EOF
html_footer =<<'EOF'
</body></html>
EOF
html_header = html_header.to_utf8
html_footer = html_footer.to_utf8

if file_type=~/txt/i 
  File.open(input_file_name, 'wb'){|temp_file|
    File.open(orign_input_file, 'rb'){|f|
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
        next if line=~/^\s*$/
          temp_file.print '<p>'+h(line)+'</p>'
      }

        temp_file.print html_footer

        puts 'end'
    }
  }
end

result = `temp/kindlegen.exe -o #{output_bare_file_name} "#{input_file_name}"`
$stderr.puts result if result.include?('Error') or !result.include?('Saving MOBI file')
puts result
File.delete(input_file_name) if no_input_file_name 
File.delete(output_path_css) if no_css_in_dir


