class Httpmon < Formula
  desc "Zero-config HTTPS MITM proxy CLI for inspecting traffic"
  homepage "https://github.com/hxddh/https-traffic-inspector"
  version "0.1.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/hxddh/https-traffic-inspector/releases/download/v#{version}/httpmon-darwin-arm64"
      sha256 "TODO_fill_in_after_release"
    else
      url "https://github.com/hxddh/https-traffic-inspector/releases/download/v#{version}/httpmon-darwin-amd64"
      sha256 "TODO_fill_in_after_release"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/hxddh/https-traffic-inspector/releases/download/v#{version}/httpmon-linux-arm64"
      sha256 "TODO_fill_in_after_release"
    else
      url "https://github.com/hxddh/https-traffic-inspector/releases/download/v#{version}/httpmon-linux-amd64"
      sha256 "TODO_fill_in_after_release"
    end
  end

  def install
    bin.install Dir["httpmon-*"][0] => "httpmon"
  end

  test do
    assert_predicate bin/"httpmon", :exist?
    assert_predicate bin/"httpmon", :executable?
  end
end
