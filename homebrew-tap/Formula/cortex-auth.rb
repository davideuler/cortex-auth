class CortexAuth < Formula
  desc "Agent-centric secrets vault: store API keys and inject them at runtime"
  homepage "https://github.com/davideuler/cortex-auth"
  version "0.1.2"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/davideuler/cortex-auth/releases/download/v#{version}/cortex-auth-v#{version}-aarch64-apple-darwin.tar.gz"
      sha256 "PLACEHOLDER_AARCH64_APPLE_DARWIN_SHA256"
    end
    on_intel do
      raise "Pre-built binaries are only available for Apple Silicon (arm64). " \
            "Please build from source: https://github.com/davideuler/cortex-auth"
    end
  end

  def install
    bin.install "cortex-server"
    bin.install "cortex-cli"
  end

  test do
    assert_predicate bin/"cortex-server", :exist?
    assert_predicate bin/"cortex-cli", :exist?
    system bin/"cortex-cli", "gen-token", "--help"
  end
end
