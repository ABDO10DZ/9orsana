# Maintainer: Abdo10dz <abdo10_dz@pm.me>
pkgname=9orsana
pkgver=1.0.0
pkgrel=1
pkgdesc="Hybrid adaptive PHP vulnerability scanner with DeepSeekR AI + CMS CLI support"
arch=('any')
url="https://github.com/abdo10dz/9orsana"
license=('GPL3')
depends=('python' 'php' 'php-ast')
optdepends=(
  'wp-cli: WordPress plugin/theme scanning'
  'jomcli: Joomla plugin/theme scanning'
  'ollama: For DeepSeek AI model execution'
  'curl: For downloading external CLI tools'
)
makedepends=('git')
source=("$pkgname::git+$url.git")
md5sums=('SKIP')

package() {
  install -Dm755 "$srcdir/$pkgname/9orsana.py" "$pkgdir/usr/bin/9orsana"
}
