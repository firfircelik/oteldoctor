# Homebrew Tap

oteldoctor can be installed via Homebrew.

## Install

```bash
brew tap firfircelik/oteldoctor
brew install oteldoctor
```

## Tap Formula

The Homebrew formula is maintained at [firfircelik/homebrew-oteldoctor](https://github.com/firfircelik/homebrew-oteldoctor).

To add oteldoctor to your own tap:

```ruby
# Formula/oteldoctor.rb
class Oteldoctor < Formula
  desc "Production-readiness analyzer for OpenTelemetry Collector configurations"
  homepage "https://github.com/firfircelik/oteldoctor"
  url "https://github.com/firfircelik/oteldoctor/releases/download/v0.1.0/oteldoctor_0.1.0_darwin_arm64.tar.gz"
  sha256 "PLACEHOLDER"
  license "MIT"

  def install
    bin.install "oteldoctor"
  end

  test do
    system "#{bin}/oteldoctor", "version"
  end
end
```

## For tap maintainers

After each release, update the formula with the new version, URLs, and SHA256 checksums. The checksums are published in `checksums.txt` on each GitHub release.
