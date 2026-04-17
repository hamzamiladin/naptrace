class Naptrace < Formula
  desc "Variant analysis, open-sourced. Feed a CVE patch, find its structural twins."
  homepage "https://github.com/hamzamiladin/naptrace"
  license "Apache-2.0"

  on_macos do
    on_arm do
      url "https://github.com/hamzamiladin/naptrace/releases/latest/download/naptrace-aarch64-apple-darwin"
      sha256 "PLACEHOLDER"
    end
    on_intel do
      url "https://github.com/hamzamiladin/naptrace/releases/latest/download/naptrace-x86_64-apple-darwin"
      sha256 "PLACEHOLDER"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/hamzamiladin/naptrace/releases/latest/download/naptrace-aarch64-unknown-linux-gnu"
      sha256 "PLACEHOLDER"
    end
    on_intel do
      url "https://github.com/hamzamiladin/naptrace/releases/latest/download/naptrace-x86_64-unknown-linux-gnu"
      sha256 "PLACEHOLDER"
    end
  end

  def install
    bin.install "naptrace-#{Hardware::CPU.arch == :arm64 ? "aarch64" : "x86_64"}-#{OS.mac? ? "apple-darwin" : "unknown-linux-gnu"}" => "naptrace"
  end

  test do
    assert_match "naptrace", shell_output("#{bin}/naptrace --version")
  end
end
