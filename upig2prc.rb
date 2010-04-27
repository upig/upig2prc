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

ʹ�÷���:
  upig2prc [options] [dirname]"
ʹ��ʾ��:
  upig2prc          #will convert all txt in current directory
  upig2prc d:/books #will convert all txt in d:/books
EOF

  options[:r] = false
  opts.on( '-r', '', '�������ļ���') do
    options[:r] = true
  end

  options[:f] = false
  opts.on( '-f', '', '�����Ѿ����ɹ���ͬ��prc') do
    options[:f] = true
  end

  opts.on( '-h', '', '����' ) do
    puts opts
    exit
  end
end

optparse.parse!

keyword = ARGV.join(' ') 

$filetypes='*.{txt}'

#temp_path 
#�ο��Ǹ���ʱ�ļ����úø�һ�´��룬�������ɱȽ�Ư����kindle�ļ�
Dir.glob("**/#{$filetypes}").each {|fileName|
  #convert txt to html
  #convert html to prc
  #puts `temp/kindlegen.exe #{fileName}`
}

`pause`
