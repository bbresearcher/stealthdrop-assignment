global CANDIDATES: Field = 2;

use dep::std;
use dep::ecrecover;

// Reused code from ZKCamp
// https://github.com/ZKCamp/noir-basics/blob/main/crypto_primitives/src/verify_signature.nr
// --------------------------- LIBRARY FUNCTIONS START --------------------------- //
fn split_u8_64(
    arr: [u8; 64]
) -> ([u8; 32], [u8; 32]) {
    let mut arr_a: [u8; 32] = [0; 32];
    let mut arr_b: [u8; 32] = [0; 32];

    for i in 0..32 {
        arr_a[i] = arr[i];
        arr_b[i] = arr[i + 32];
    };

    (arr_a, arr_b)
}

// --------------------------- LIBRARY FUNCTIONS END --------------------------- //

fn main(
  pub_key: [u8; 64],
  signature: [u8; 64],
  hashed_message: pub [u8; 32],
  polynomial: [Field; CANDIDATES + 1],
  polynomial_commitment: Field,
  nullifier: pub [u8; 32],
) {
  
  // First validate the ECDSA signature
  let (pub_key_x, pub_key_y) = split_u8_64(pub_key);
  let key = ecrecover::secp256k1::PubKey::from_xy(pub_key_x, pub_key_y);
  let valid_signature = key.verify_sig(signature, hashed_message);
  assert(valid_signature);

  // recover address
  let sender_addres = key.ecrecover(signature, hashed_message);
  // check inclusion of address in polynomial
  let checked_polynomial = evaluate_polynomial(polynomial,sender_addres);
  assert(checked_polynomial == 0);

  // now check that the hash of the polynimial is the same as the polynomial_commitment
  let poly_hash = std::hash::pedersen(polynomial);
  assert(polynomial_commitment == poly_hash[0]);


  // Check nullifier is a hash of the address
  let nullfier_hash = std::hash::blake2s(signature);
  assert(nullfier_hash==nullifier);

}

fn evaluate_polynomial(polynomial: [Field; CANDIDATES + 1], x: Field) -> Field {
  // Formula is (x - a) * (x - b)
  // recovered address is 0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266
  let mut multiplied = 1;
  let mut poly_field = 0;
  for i in 0..CANDIDATES+1{
      poly_field = polynomial[i] * multiplied + poly_field;
      multiplied = multiplied * x;
  }
  std::println(poly_field);
  //assert(poly_field == 0);
  
  poly_field
}

#[test]
fn test_main() {
  let pub_key = [131,  24,  83,  91,  84,  16,  93,  74,  122,  174,  96,  192,  143,  196,  95,  150,  135,  24,  27,  79,  223,  198,  37,  189,  26,  117,  63,  167,  57,  127,  237,  117,  53,  71,  241,  28,  168,  105,  102,  70,  242,  243,  172,  176,  142,  49,  1,  106,  250,  194,  62,  99,  12,  93,  17,  245,  159,  97,  254,  245,  123,  13,  42,  165];
  let signature = [1,  83,  82,  167,  184,  77,  226,  104,  5,  27,  151,  91,  202,  127,  17,  183,  75,  31,  190,  253,  159,  116,  155,  13,  24,  178,  40,  165,  129,  90,  103,  204,  42,  164,  230,  62,  73,  181,  169,  61,  251,  221,  128,  221,  14,  19,  179,  25,  107,  132,  10,  188,  149,  0,  197,  52,  151,  239,  244,  103,  215,  224,  56,  242];

  let hashed_message = [3,  57, 199, 96, 145, 58, 183, 241, 206, 140, 36, 34, 165, 163, 17, 210, 97, 254, 154, 79, 91, 223, 149, 18, 3, 210, 111, 56, 246, 219, 19, 104];

  let polynomial = [
    0x0832c9fedf291cc3adf56eefd21ac09630c66ad67747329385c9fcfc7cbf8d38,
    0x30644e72e131a029b85045b51d480807486e4c754ae9f95bbfba6db6d86a63d3,
    0x01
  ];

  let polynomial_commitment = 0x1eceef64088bbbeb280bee01b3f4e611137e8d0ac5a868f538e4617df5c62ec2;
  let nullifier = [142,  197,  227,  35,  35,  142,  255,  176,  38,  63,  247,  168,  33,  178,  55,  202,  46,  76,  167,  202,  130,  208,  59,  14,  151,  19,  144,  228,  58,  37,  10,  101];

  main(pub_key, signature, hashed_message, polynomial, polynomial_commitment, nullifier);
}

