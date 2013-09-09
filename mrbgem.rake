
MRuby::Gem::Specification.new('mruby-pcap') do |spec|
  spec.license = 'MIT'
  spec.authors = 'Julien Ammous'
  
  spec.linker.libraries << %w(pcap)
end
