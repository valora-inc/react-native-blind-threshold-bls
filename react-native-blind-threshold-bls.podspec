require "json"

package = JSON.parse(File.read(File.join(__dir__, "package.json")))

Pod::Spec.new do |s|
  s.name         = "react-native-blind-threshold-bls"
  s.version      = package["version"]
  s.summary      = package["description"]
  s.description  = <<-DESC
                  react-native-blind-threshold-bls
                   DESC
  s.homepage     = "https://github.com/celo-org/react-native-blind-threshold-bls"
  s.license      = "Apache 2.0"
  s.authors      = { "Celo" => "support@celo.org" }
  s.platforms    = { :ios => "9.0" }
  s.source       = { :git => "https://github.com/celo-org/react-native-blind-threshold-bls", :tag => "#{s.version}" }

  s.source_files = "ios/**/*.{h,m,swift}"
  s.ios.vendored_library = 'ios/Libraries/libblind_threshold_bls.a'
  s.requires_arc = true

  s.dependency "React-Core"
  # ...
  # s.dependency "..."
end

