# Place this file at Formula/moat.rb in a repo named `homebrew-tap`
# (e.g. github.com/nunomaduro/homebrew-tap), then users run:
#   brew install nunomaduro/tap/moat
#
# After each release, update `version` and the four `sha256` values from
# the SHA256SUMS file attached to the GitHub release.

class Moat < Formula
  desc "Supply-chain security auditor for GitHub organizations"
  homepage "https://github.com/nunomaduro/moat"
  version "0.1.0"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/nunomaduro/moat/releases/download/v#{version}/moat-#{version}-aarch64-apple-darwin.tar.gz"
      sha256 "REPLACE_WITH_AARCH64_APPLE_DARWIN_SHA256"
    end
    on_intel do
      url "https://github.com/nunomaduro/moat/releases/download/v#{version}/moat-#{version}-x86_64-apple-darwin.tar.gz"
      sha256 "REPLACE_WITH_X86_64_APPLE_DARWIN_SHA256"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/nunomaduro/moat/releases/download/v#{version}/moat-#{version}-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "REPLACE_WITH_AARCH64_LINUX_SHA256"
    end
    on_intel do
      url "https://github.com/nunomaduro/moat/releases/download/v#{version}/moat-#{version}-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "REPLACE_WITH_X86_64_LINUX_SHA256"
    end
  end

  def install
    bin.install "moat"
  end

  test do
    assert_match "moat", shell_output("#{bin}/moat --help")
  end
end
