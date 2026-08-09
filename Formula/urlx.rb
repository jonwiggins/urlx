class Urlx < Formula
  desc "Memory-safe command-line URL transfer tool — drop-in replacement for curl"
  homepage "https://github.com/jonwiggins/urlx"
  url "https://github.com/jonwiggins/urlx/archive/refs/tags/v0.3.0.tar.gz"
  sha256 "e392a9da2b52297f853f580c8fa2bb56802f817aee75d42cd681ebba3fdb1b5d"
  license "MIT"

  depends_on "rust" => :build

  def install
    system "cargo", "install", *std_cargo_args(path: "crates/urlx-cli")
  end

  test do
    assert_match "urlx", shell_output("#{bin}/urlx --version")
  end
end
