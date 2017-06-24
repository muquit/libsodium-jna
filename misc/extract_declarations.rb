#!/usr/bin/env ruby

# 
# extract funcition declarations from sodium header files
# muquit@muquit.com 
class ExtractFuncs
  def initialize
    @regex = /^int|^size_t|^const|^unsigned|^long|^char.+$/
  end

  def doit
    ARGV.each do |file|
      lines = File.readlines(file)
      lines.each_with_index do |val,idx|
        line = lines[idx]
        line.chomp! if line
        next if line.length == 0
        if line =~ @regex
          if line =~ /;$/
            puts line
            next
          else
            puts "#{line}"
            idx = idx + 1
            line = lines[idx];
            while line !~ /\;$/
              idx = idx + 1
              l = lines[idx];
              if l =~ /attribute.+;$/
                puts ";"
              else
                puts "#{l}"
              end
              if l =~ /\;$/
                break
              end
            end
          end
        end
      end
    end
  end
end

if __FILE__ == $0
  ExtractFuncs.new().doit()
end
