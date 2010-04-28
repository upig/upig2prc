set rubyopt=
:: begin long line
ruby rubyscript2exe.rb %1 --rubyscript2exe-verbose
:: end long line
set rubyopt=-rubygems
pause

