#xiangwei 31531640@qq.com

require 'rubygems'
require 'optparse'
exit if Object.const_defined?(:Ocra)

options = {}

optparse = OptionParser.new do|opts|
  # Set a banner, displayed at the top
  # of the help screen.
  opts.banner =<<'EOF'
批量转换txt文件为prc文档(Kindle使用）
1. 自动排版txt文件
2. 自动调整prc格式

使用方法:
  upig2prc [options] [dirname]"
使用示例:
  upig2prc          #will convert all txt in current directory
  upig2prc d:/books #will convert all txt in d:/books
EOF

  options[:r] = false
  opts.on( '-r', '', '遍历子文件夹') do
    options[:r] = true
  end

  options[:f] = false
  opts.on( '-f', '', '覆盖已经生成过的同名prc') do
    options[:f] = true
  end

  opts.on( '-h', '', '帮助' ) do
    puts opts
    exit
  end
end

optparse.parse!

keyword = ARGV.join(' ') 

$filetypes='*.{txt}'

#temp_path 
#参考那个临时文件，好好改一下代码，可以生成比较漂亮的kindle文件
Dir.glob("**/#{$filetypes}").each {|fileName|
  #convert txt to html
  #convert html to prc
  #puts `temp/kindlegen.exe #{fileName}`
}

`pause`
