class Urlx < Formula
  desc "Memory-safe command-line URL transfer tool — drop-in replacement for curl"
  homepage "https://github.com/jonwiggins/urlx"
  url "https://github.com/jonwiggins/urlx/archive/refs/tags/v0.2.0.tar.gz"
  sha256 "8e1999c5009618674f7e9edf07cfe33790dbc5cb07d5b3ea668b44ca5dfd841a"
  license "MIT"

  depends_on "rust" => :build

  def install
    system "cargo", "install", *std_cargo_args(path: "crates/urlx-cli")
  end

  test do
    assert_match "urlx", shell_output("#{bin}/urlx --version")
  end
end
