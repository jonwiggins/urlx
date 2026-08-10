class Urlx < Formula
  desc "Memory-safe command-line URL transfer tool — drop-in replacement for curl"
  homepage "https://github.com/jonwiggins/urlx"
  url "https://github.com/jonwiggins/urlx/archive/refs/tags/v0.3.1.tar.gz"
  sha256 "0c3967031a5b40c2bfced049730951037989ce1918d9df167b8cb39a9d1955ae"
  license "MIT"

  depends_on "rust" => :build

  def install
    system "cargo", "install", *std_cargo_args(path: "crates/urlx-cli")
  end

  test do
    assert_match "urlx", shell_output("#{bin}/urlx --version")
  end
end
