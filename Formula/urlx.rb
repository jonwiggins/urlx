class Urlx < Formula
  desc "Memory-safe command-line URL transfer tool — drop-in replacement for curl"
  homepage "https://github.com/jonwiggins/urlx"
  url "https://github.com/jonwiggins/urlx/archive/refs/tags/v0.1.0.tar.gz"
  sha256 ""  # Will be filled after tagging v0.1.0
  license "MIT"

  depends_on "rust" => :build

  def install
    system "cargo", "install", *std_cargo_args(path: "crates/urlx-cli")
  end

  test do
    assert_match "urlx", shell_output("#{bin}/urlx --version")
  end
end
