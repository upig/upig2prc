#xiangwei 31531640@qq.com

require 'rubygems'
require 'optparse'
require 'jcode'
require 'iconv'  
require 'rchardet'

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
����ת��txt�ļ�Ϊprc�ĵ�(Kindleʹ�ã�
1. �Զ��Ű�txt�ļ�
2. �Զ�����prc��ʽ
3. �Զ�ʶ������ʽ
ʹ�÷���:
  upig2prc [options] file_name"
EOF

  options[:temp] = 'upig2prc_temp.html' 
  opts.on( '-t', '--temp output_name', 'ָ����ʱ�ļ���') do |f|
    options[:temp] = f 
  end

  options[:output] = ''
  opts.on( '-o', '--output output_name', 'ָ������ļ���') do |f|
    options[:output] = f 
  end

  opts.on( '-h', '--help', '����' ) do
    puts opts
    exit
  end
end

optparse.parse!

keyword = ARGV.join(' ') 
options[:output] = File.basename(keyword, '.txt')+'.prc' if options[:output] == ''

$stderr.puts optparse if keyword.strip==''


html_header =<<'EOF'
<html><head><meta http-equiv="Content-Type" content="text/html; charset=utf-8"><link REL="stylesheet" TYPE="text/css" HREF="xiang.css"></head><body topmargin="0" leftmargin="0" bottommargin="0" rightmargin="0">
EOF
html_footer =<<'EOF'
</body></html>
EOF

html_header = html_header.to_utf8
html_footer = html_footer.to_utf8

File.open(options[:temp], 'w'){|temp_file|
  File.open(keyword, 'r'){|f|
    src_str = f.read
    encode_det = CharDet.detect(src_str)
    encoding = encode_det['encoding'].upcase
    confidence = encode_det['confidence']
    $stderr.puts '���벻����ȷʶ��' if confidence <0.1

    temp_file.print html_header

    src_str_utf8 = src_str.to_utf8(encoding)
    src_str_utf8.each_line {|line|
      line.gsub!('��'.to_utf8, '  '.to_utf8)
      line.lstrip!
      temp_file.print '<p>'+line+'</p>'
    }

    temp_file.print html_footer
  }
}

`temp/kindlegen.exe #{options[:temp]} -o #{options[:output]}`

#$filetypes='*.{txt}'



#puts options


#convert html to prc

#temp_path 
#�ο��Ǹ���ʱ�ļ����úø�һ�´��룬�������ɱȽ�Ư����kindle�ļ�
#Dir.glob("**/#{$filetypes}").each {|fileName|
  #convert txt to html
  #convert html to prc
  #puts `temp/kindlegen.exe #{fileName}`
#}

