#include "crypto.h"
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>

cmls_CipherSuite cmls_ciphersuites[] = {
	{
		.hash        = SHA256,
		.hash_name   = SN_sha256,
		.hash_length = SHA256_DIGEST_LENGTH,

		.key_sign_type = EVP_PKEY_ED25519,
		.key_hpke_type = EVP_PKEY_X25519,

		.hpke_suite =
			(OSSL_HPKE_SUITE){
				.kem_id  = OSSL_HPKE_KEM_ID_X25519,
				.aead_id = OSSL_HPKE_AEAD_ID_AES_GCM_128,
				.kdf_id  = OSSL_HPKE_KDF_ID_HKDF_SHA256,
			},
	},
	{
		.skip = true,

		.hash        = SHA256,
		.hash_name   = SN_sha256,
		.hash_length = SHA256_DIGEST_LENGTH,

		.key_sign_type = EVP_PKEY_EC,
		.key_hpke_type = EVP_PKEY_EC,
		.key_group     = "prime256v1",

		.hpke_suite =
			(OSSL_HPKE_SUITE){
				.kem_id  = OSSL_HPKE_KEM_ID_P256,
				.aead_id = OSSL_HPKE_AEAD_ID_AES_GCM_128,
				.kdf_id  = OSSL_HPKE_KDF_ID_HKDF_SHA256,
			},
	},
	{
		.hash        = SHA256,
		.hash_name   = SN_sha256,
		.hash_length = SHA256_DIGEST_LENGTH,

		.key_sign_type = EVP_PKEY_ED25519,
		.key_hpke_type = EVP_PKEY_X25519,

		.hpke_suite =
			(OSSL_HPKE_SUITE){
				.kem_id  = OSSL_HPKE_KEM_ID_X25519,
				.aead_id = OSSL_HPKE_AEAD_ID_CHACHA_POLY1305,
				.kdf_id  = OSSL_HPKE_KDF_ID_HKDF_SHA256,
			},
	},
	{
		.hash        = SHA512,
		.hash_name   = SN_sha512,
		.hash_length = SHA512_DIGEST_LENGTH,

		.key_sign_type = EVP_PKEY_ED448,
		.key_hpke_type = EVP_PKEY_X448,

		.hpke_suite =
			(OSSL_HPKE_SUITE){
				.kem_id  = OSSL_HPKE_KEM_ID_X448,
				.aead_id = OSSL_HPKE_AEAD_ID_AES_GCM_256,
				.kdf_id  = OSSL_HPKE_KDF_ID_HKDF_SHA512,
			},
	},
	{
		.skip = true,

		.hash        = SHA512,
		.hash_name   = SN_sha512,
		.hash_length = SHA512_DIGEST_LENGTH,

		.key_sign_type = EVP_PKEY_EC,
		.key_hpke_type = EVP_PKEY_EC,
		.key_group     = "secp521r1",

		.hpke_suite =
			(OSSL_HPKE_SUITE){
				.kem_id  = OSSL_HPKE_KEM_ID_P521,
				.aead_id = OSSL_HPKE_AEAD_ID_AES_GCM_256,
				.kdf_id  = OSSL_HPKE_KDF_ID_HKDF_SHA512,
			},
	},
	{
		.hash        = SHA512,
		.hash_name   = SN_sha512,
		.hash_length = SHA512_DIGEST_LENGTH,

		.key_sign_type = EVP_PKEY_ED448,
		.key_hpke_type = EVP_PKEY_X448,

		.hpke_suite =
			(OSSL_HPKE_SUITE){
				.kem_id  = OSSL_HPKE_KEM_ID_X448,
				.aead_id = OSSL_HPKE_AEAD_ID_CHACHA_POLY1305,
				.kdf_id  = OSSL_HPKE_KDF_ID_HKDF_SHA512,
			},
	},
	{
		.skip = true,

		.hash        = SHA384,
		.hash_name   = SN_sha384,
		.hash_length = SHA384_DIGEST_LENGTH,

		.key_sign_type = EVP_PKEY_EC,
		.key_hpke_type = EVP_PKEY_EC,
		.key_group     = "secp384r1",

		.hpke_suite =
			(OSSL_HPKE_SUITE){
				.kem_id  = OSSL_HPKE_KEM_ID_P384,
				.aead_id = OSSL_HPKE_AEAD_ID_AES_GCM_256,
				.kdf_id  = OSSL_HPKE_KDF_ID_HKDF_SHA384,
			},
	},
};

size_t cmls_max_ciphersuite =
	sizeof(cmls_ciphersuites) / sizeof(cmls_ciphersuites[0]);
