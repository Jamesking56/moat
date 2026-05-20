# This repo doubles as a Homebrew tap. Users install with:
#   brew install laravel/moat/moat
#
# This file is updated automatically by the release workflow.

class Moat < Formula
  desc "security posture auditing for your github organization & repositories"
  homepage "https://github.com/laravel/moat"
  version "1.0.1"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/laravel/moat/releases/download/v#{version}/moat-#{version}-aarch64-apple-darwin.tar.gz"
      sha256 "c1575712c5b3724d32900f8887c5982bd296405ad6d8e6731cced27be5c3944d"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/laravel/moat/releases/download/v#{version}/moat-#{version}-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "04e2743db5f7c1794cc45524bd6548065597bb2112d61a031238df00950385bf"
    end
    on_intel do
      url "https://github.com/laravel/moat/releases/download/v#{version}/moat-#{version}-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "1c5947113343bc8c536b8bf789540624093e0c1aa05afea4839ad384562f5c3c"
    end
  end

  def install
    bin.install "moat"
  end

  test do
    assert_match "moat", shell_output("#{bin}/moat --help")
  end
end
