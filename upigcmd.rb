#xiangwei 31531640@qq.com

require 'rubygems'
require 'optparse'
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

  options[:temp] = 'upig_temp.tmp' 
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

$stderr.puts optparse if keyword.strip==''
#$stderr.puts "options"

File.open(options[:temp], 'w'){|f|
  #f.write(optparse.to_s)
}

#$filetypes='*.{txt}'



#puts options

#convert txt to html

#convert html to prc

#temp_path 
#�ο��Ǹ���ʱ�ļ����úø�һ�´��룬�������ɱȽ�Ư����kindle�ļ�
#Dir.glob("**/#{$filetypes}").each {|fileName|
  #convert txt to html
  #convert html to prc
  #puts `temp/kindlegen.exe #{fileName}`
#}

