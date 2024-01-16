#include "crypto.h"
#include <assert.h>
#include <openssl/evp.h>

void cmls_crypto_test(const json_t* entry) {
	size_t suite_index_1 =
		json_integer_value(json_object_get(entry, "cipher_suite"));

	if(suite_index_1 > cmls_max_ciphersuite) {
		fprintf(
			stderr,
			"\e[1;31mUnsupported cipher suite: %zu\e[m\n",
			suite_index_1
		);
		return;
	}

	cmls_CipherSuite suite = cmls_ciphersuites[suite_index_1 - 1];
	if(suite.skip) {
		fprintf(
			stderr,
			"\e[1;31mSkipping cipher suite: %zu\e[m\n",
			suite_index_1
		);
		return;
	}

	///// RefHash /////
	{
		const json_t* j     = json_object_get(entry, "ref_hash");
		const char*   label = json_string_value(json_object_get(j, "label"));

		bytes data = decode_hex(json_string_value(json_object_get(j, "value")));

		bytes hash_want =
			decode_hex(json_string_value(json_object_get(j, "out")));

		bytes hash_have = cmls_crypto_RefHash(suite, label, data);
		assert(hash_want.len == hash_have.len);
		assert(memcmp(hash_want.ptr, hash_have.ptr, hash_want.len) == 0);

		vec_free(&hash_have);
		vec_free(&hash_want);
		vec_free(&data);
	}

	///// ExpandWithLabel /////
	{
		const json_t* j = json_object_get(entry, "expand_with_label");

		bytes context =

			decode_hex(json_string_value(json_object_get(j, "context")));

		const char* label = json_string_value(json_object_get(j, "label"));

		size_t length = json_integer_value(json_object_get(j, "length"));

		bytes secret =
			decode_hex(json_string_value(json_object_get(j, "secret")));

		bytes out_want =
			decode_hex(json_string_value(json_object_get(j, "out")));

		bytes out_have =
			cmls_crypto_ExpandWithLabel(suite, secret, label, context, length);
		assert(out_want.len == out_have.len);
		assert(memcmp(out_want.ptr, out_have.ptr, out_want.len) == 0);

		vec_free(&out_have);
		vec_free(&out_want);
		vec_free(&secret);
		vec_free(&context);
	}

	///// DeriveSecret /////
	{
		const json_t* j = json_object_get(entry, "derive_secret");

		const char* label = json_string_value(json_object_get(j, "label"));

		bytes secret =
			decode_hex(json_string_value(json_object_get(j, "secret")));

		bytes out_want =
			decode_hex(json_string_value(json_object_get(j, "out")));

		bytes out_have = cmls_crypto_DeriveSecret(suite, secret, label);
		assert(out_want.len == out_have.len);
		assert(memcmp(out_want.ptr, out_have.ptr, out_want.len) == 0);

		vec_free(&out_have);
		vec_free(&out_want);
		vec_free(&secret);
	}

	///// DeriveTreeSecret /////
	{
		const json_t* j = json_object_get(entry, "derive_tree_secret");

		uint32_t generation =
			json_integer_value(json_object_get(j, "generation"));

		const char* label = json_string_value(json_object_get(j, "label"));

		size_t length = json_integer_value(json_object_get(j, "length"));

		bytes secret =
			decode_hex(json_string_value(json_object_get(j, "secret")));

		bytes out_want =
			decode_hex(json_string_value(json_object_get(j, "out")));

		bytes out_have = cmls_crypto_DeriveTreeSecret(
			suite,
			secret,
			label,
			generation,
			length
		);
		assert(out_want.len == out_have.len);
		assert(memcmp(out_want.ptr, out_have.ptr, out_want.len) == 0);

		vec_free(&out_have);
		vec_free(&out_want);
		vec_free(&secret);
	}

	///// SignWithLabel /////
	{
		const json_t* j = json_object_get(entry, "sign_with_label");

		bytes content =
			decode_hex(json_string_value(json_object_get(j, "content")));

		const char* label = json_string_value(json_object_get(j, "label"));

		bytes priv = decode_hex(json_string_value(json_object_get(j, "priv")));

		bytes pub = decode_hex(json_string_value(json_object_get(j, "pub")));

		bytes sig_want =
			decode_hex(json_string_value(json_object_get(j, "signature")));

		EVP_PKEY* secret_key =
			cmls_crypto_mkKey(suite, priv, MKKEY_SECRET | MKKEY_SIGN);
		EVP_PKEY* public_key =
			cmls_crypto_mkKey(suite, pub, MKKEY_PUBLIC | MKKEY_SIGN);

		assert(cmls_crypto_VerifyWithLabel(public_key, label, content, sig_want)
		);

		bytes sig_have = cmls_crypto_SignWithLabel(secret_key, label, content);
		assert(sig_want.len == sig_have.len);
		assert(memcmp(sig_want.ptr, sig_have.ptr, sig_want.len) == 0);
		assert(cmls_crypto_VerifyWithLabel(public_key, label, content, sig_have)
		);

		EVP_PKEY_free(public_key);
		EVP_PKEY_free(secret_key);

		vec_free(&sig_have);
		vec_free(&sig_want);
		vec_free(&pub);
		vec_free(&priv);
		vec_free(&content);
	}

	///// EncryptWithLabel /////
	{
		const json_t* j = json_object_get(entry, "encrypt_with_label");

		bytes ciphertext_want =
			decode_hex(json_string_value(json_object_get(j, "ciphertext")));

		bytes context =
			decode_hex(json_string_value(json_object_get(j, "context")));

		bytes kem_output_want =
			decode_hex(json_string_value(json_object_get(j, "kem_output")));

		const char* label = json_string_value(json_object_get(j, "label"));

		bytes plaintext_want =
			decode_hex(json_string_value(json_object_get(j, "plaintext")));

		bytes priv = decode_hex(json_string_value(json_object_get(j, "priv")));

		bytes pub = decode_hex(json_string_value(json_object_get(j, "pub")));

		EVP_PKEY* key =
			cmls_crypto_mkKey(suite, priv, MKKEY_SECRET | MKKEY_HPKE);

		bytes plaintext_have_1 = cmls_crypto_DecryptWithLabel(
			suite,
			key,
			label,
			context,
			kem_output_want,
			ciphertext_want
		);
		assert(plaintext_want.len == plaintext_have_1.len);
		assert(
			memcmp(
				plaintext_want.ptr,
				plaintext_have_1.ptr,
				plaintext_want.len
			) == 0
		);

		bytes kem_output_have = {0};
		bytes ciphertext_have = {0};
		cmls_crypto_EncryptWithLabel(
			suite,
			pub,
			label,
			context,
			plaintext_have_1,
			&kem_output_have,
			&ciphertext_have
		);

		bytes plaintext_have_2 = cmls_crypto_DecryptWithLabel(
			suite,
			key,
			label,
			context,
			kem_output_have,
			ciphertext_have
		);
		assert(plaintext_want.len == plaintext_have_2.len);
		assert(
			memcmp(
				plaintext_want.ptr,
				plaintext_have_2.ptr,
				plaintext_want.len
			) == 0
		);

		EVP_PKEY_free(key);

		vec_free(&plaintext_have_2);
		vec_free(&ciphertext_have);
		vec_free(&kem_output_have);
		vec_free(&plaintext_have_1);
		vec_free(&pub);
		vec_free(&priv);
		vec_free(&plaintext_want);
		vec_free(&kem_output_want);
		vec_free(&context);
		vec_free(&ciphertext_want);
	}
}
