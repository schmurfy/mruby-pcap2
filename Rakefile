
task :default => :test

task :test do
  config_path = File.expand_path('../test_conf.Rb', __FILE__)
  Dir.chdir('/Users/Schmurfy/Dev/personal/mruby') do
    sh "MRUBY_CONFIG=#{config_path} rake"
  end
  
  puts ""
  
  sh "./build/bin/mruby test.rb"
end
