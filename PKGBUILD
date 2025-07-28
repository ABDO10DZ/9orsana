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
makedepends=('git' 'composer')  # Added composer as build dependency
source=("$pkgname::git+$url.git")
md5sums=('SKIP')

prepare() {
  cd "$srcdir/$pkgname"

  # Install PHP dependencies using composer
  COMPOSER_ALLOW_SUPERUSER=1 composer install --no-dev --optimize-autoloader
}

package() {
  cd "$srcdir/$pkgname"

  # Install Python script
  install -Dm755 "9orsana.py" "$pkgdir/usr/bin/9orsana"

  # Install PHP files with vendor/ to /usr/share/9orsana
  install -d "$pkgdir/usr/share/9orsana"
  cp -r *.php vendor/ composer.* "$pkgdir/usr/share/9orsana"
}
