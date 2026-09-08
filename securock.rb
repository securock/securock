class Securock < Formula
  desc "Supply-chain trust layer for software dependencies"
  homepage "https://securock.dev"
  license "Apache-2.0"
  head "https://github.com/securock/securock.git", branch: "main"

  depends_on "go" => :build

  def install
    ldflags = %W[
      -s -w
      -X main.version=HEAD
    ]
    system "go", "build", *std_go_args(ldflags:), "./cmd/securock"
  end

  test do
    assert_match "securock", shell_output("#{bin}/securock version")
  end
end
