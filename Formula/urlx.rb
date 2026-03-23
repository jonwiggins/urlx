class Urlx < Formula
  desc "Memory-safe command-line URL transfer tool — drop-in replacement for curl"
  homepage "https://github.com/jonwiggins/urlx"
  url "https://github.com/jonwiggins/urlx/archive/refs/tags/v0.2.0.tar.gz"
  sha256 "PLACEHOLDER"
  license "MIT"

  depends_on "rust" => :build

  def install
    system "cargo", "install", *std_cargo_args(path: "crates/urlx-cli")
  end

  test do
    assert_match "urlx", shell_output("#{bin}/urlx --version")
  end
end
