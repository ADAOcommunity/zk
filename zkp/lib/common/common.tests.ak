use aiken/math.{pow}
use common/common.{bls12_381_prime, mod_pow, mod_sqrt}

test mod_pow_tests() {
  // low integer tests
  expect mod_pow(2, 0) == 1
  expect mod_pow(2, 1) == 2

  // confirm modulo falls into range 10^76, 10^77
  expect mod_pow(10, 76) == pow(10, 76)
  expect mod_pow(10, 77) < pow(10, 77)

  // confirm modulo falls into range 2^254, 2^255
  expect mod_pow(2, 254) == pow(2, 254)
  expect mod_pow(2, 255) < pow(2, 255)

  // explicit numerical tests
  expect
    mod_pow(2, 255) == 5460169443531907232337751996157988088944439832292644197125133304017983635455
  expect
    mod_pow(2, 256) == 10920338887063814464675503992315976177888879664585288394250266608035967270910
  expect
    mod_pow(2, 257) == 21840677774127628929351007984631952355777759329170576788500533216071934541820
  expect
    mod_pow(2, 258) == 43681355548255257858702015969263904711555518658341153577001066432143869083640

  // very large exponents
  expect mod_pow(2, bls12_381_prime) == 2
  expect mod_pow(2, bls12_381_prime - 1) == 1
  expect mod_pow(2, bls12_381_prime + 8) == 512
  expect mod_pow(2, bls12_381_prime * 5) == 32
  expect
    mod_pow(
      5,
      43681355548255257858702015969263904711555518658341153577001066432143869083640,
    ) == 14864253341600970011638951329452085181913896235107598824945200969537057936636
}
