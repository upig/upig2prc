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
3. 自动识别编码格式
使用方法:
  upig2prc [options] file_name"
EOF

  options[:temp] = 'upig_temp.tmp' 
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
#参考那个临时文件，好好改一下代码，可以生成比较漂亮的kindle文件
#Dir.glob("**/#{$filetypes}").each {|fileName|
  #convert txt to html
  #convert html to prc
  #puts `temp/kindlegen.exe #{fileName}`
#}

