#include "erl_nif.h"

#include <stdlib.h>
#include <string.h>

// openssl
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>


#define B_FORMAT_TEXT   0x8000
#define FORMAT_PEM     (5 | B_FORMAT_TEXT)

//
// atoms
//

static ERL_NIF_TERM atom_error;
static ERL_NIF_TERM atom_ok;
static ERL_NIF_TERM atom_bad_keylen;
static ERL_NIF_TERM atom_bad_ssl_init;
static ERL_NIF_TERM atom_bad_args;

//

static int load(ErlNifEnv* env, void** priv_data, ERL_NIF_TERM load_info) {

    atom_bad_ssl_init = enif_make_atom(env,"bad_ssl_init");
    atom_bad_keylen   = enif_make_atom(env,"bad_keylen");
    atom_bad_args     = enif_make_atom(env,"bad_args");
    atom_error        = enif_make_atom(env,"error");
    atom_ok           = enif_make_atom(env,"ok");

    return 0;
}

static int upgrade(ErlNifEnv* env, void** priv_data, void** old_priv_data,
                   ERL_NIF_TERM load_info) {
    load(env, priv_data, load_info);
    return 0;
}

//////////////////////////////////////
//////////////////////////////////////
//////////////////////////////////////

ERL_NIF_TERM
rsa_generate_key_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {

  ERL_NIF_TERM ret, private_keyterm, public_keyterm;
  BIO *bio_private_pem = NULL, *bio_public_pem = NULL;
  RSA *rsa = NULL;
  const EVP_CIPHER *enc = EVP_des_ede3_cbc();
  BIGNUM *bn_rsa_genkey=NULL;
  int dlen, private_pemlen, public_pemlen, rsa_keylen = 2048; // keylen 2048
  unsigned long f4 = RSA_F4;
  char password[1024];

  /* get password from zero index argument */
  if (!enif_get_string(env, argv[0], password, sizeof(password) - 1, ERL_NIF_LATIN1)) {
    return enif_make_tuple2(env, atom_error, atom_bad_args);
  }

  /////

  rsa = RSA_new();
  bn_rsa_genkey = BN_new();
  bio_private_pem = BIO_new(BIO_s_mem());
  bio_public_pem = BIO_new(BIO_s_mem());

  /* OpenSSL */
  if(rsa && bn_rsa_genkey && bio_private_pem && bio_public_pem){
    BN_set_word(bn_rsa_genkey, f4);

    if (RSA_generate_key_ex(rsa, rsa_keylen, bn_rsa_genkey, NULL)) {
      unsigned char *private_pemdata;
      unsigned char *public_pemdata;

      PEM_write_bio_RSA_PUBKEY(bio_public_pem,rsa);
      PEM_write_bio_RSAPrivateKey(bio_private_pem, rsa, enc, NULL, 0, 0, password);

      private_pemlen = BIO_get_mem_data(bio_private_pem, &private_pemdata);
      public_pemlen = BIO_get_mem_data(bio_public_pem, &public_pemdata);

      dlen = sizeof(int)+private_pemlen+sizeof(int)+public_pemlen;
      private_pemdata[private_pemlen]=0;
      public_pemdata[public_pemlen]=0;

      memcpy(enif_make_new_binary(env, private_pemlen, &private_keyterm), private_pemdata, private_pemlen);
      memcpy(enif_make_new_binary(env, public_pemlen, &public_keyterm), public_pemdata, public_pemlen);

      ret = enif_make_tuple3(env, atom_ok, private_keyterm, public_keyterm);
    } else {
      ret = enif_make_tuple2(env, atom_error, atom_bad_keylen);
    }

  } else {
    ret = enif_make_tuple2(env, atom_error, atom_bad_ssl_init);
  }

  /* dealloc */
  if(bio_private_pem)
    BIO_free_all(bio_private_pem);
  if(bio_public_pem)
    BIO_free_all(bio_public_pem);
  if(bn_rsa_genkey)
    BN_free(bn_rsa_genkey);
  if(rsa)
    RSA_free(rsa);

  return ret;
}

//
// encrypt
// openssl rsautl -in test.txt -out test123.enc -pubin -inkey pub_key.der -encrypt
//

ERL_NIF_TERM //ENCRYPT
rsa_encrypt(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
  ErlNifBinary data_bin, keyfile, ret_bin;
  RSA* rsa = RSA_new();
  ENGINE *e = NULL;
  int padding, i, k;
  int rsa_inlen, keyformat = FORMAT_PEM, keysize, ret = 1;
  int rsa_outlen = 0;
  unsigned char *rsa_in = NULL, *rsa_out = NULL, pad = RSA_PKCS1_PADDING;
  FILE *f;

  BIO *key = BIO_new(BIO_s_mem());
  EVP_PKEY *pkey = NULL;

  padding = RSA_PKCS1_PADDING; // 1

  if (!enif_inspect_binary(env, argv[0], &data_bin)
      || !enif_inspect_binary(env, argv[1], &keyfile)) {
    RSA_free(rsa);
	  return enif_make_badarg(env);
  }

  f = fopen("./priv/pub_key.der", "rb");
  //PEM_read_bio_PUBKEY
  //BIO_write(key, &keyfile, sizeof(keyfile))
  pkey = PEM_read_PUBKEY(f, NULL, NULL, NULL);
  rsa = EVP_PKEY_get1_RSA(pkey);
  EVP_PKEY_free(pkey);

  enif_alloc_binary(RSA_size(rsa), &ret_bin);

  i = RSA_public_encrypt(data_bin.size, data_bin.data,
                         ret_bin.data, rsa, 1);

  ///

  //return enif_make_int(env, i);
  //return enif_make_string(env, (const char *)ret_bin.data, ERL_NIF_LATIN1);
  //return enif_make_int(env, ret_bin.size);

  if (i > 0) {
    return enif_make_binary(env,&ret_bin);
  } else {
    enif_release_binary(&ret_bin);
    return enif_make_tuple2(env, atom_error, atom_bad_ssl_init);
  }
}

//
// decrypt
// openssl rsautl -in test123.enc -inkey priv_key.pem -decrypt -passin pass:123456
//

ERL_NIF_TERM //ENCRYPT
rsa_decrypt(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
  ErlNifBinary data_bin, keyfile, ret_bin;
  RSA* rsa = NULL;
  ENGINE *e = NULL;
  int padding, i, k;
  int rsa_inlen, keyformat = FORMAT_PEM, keysize, ret = 1;
  int rsa_outlen = 0;
  unsigned char *rsa_in = NULL, *rsa_out = NULL, pad = RSA_PKCS1_PADDING;
  FILE *fp;
  BIO *key = BIO_new(BIO_s_mem());
  EVP_PKEY *pkey = NULL;
  char password[2048];

  padding = RSA_PKCS1_PADDING; // 1

  if (!enif_inspect_binary(env, argv[0], &data_bin)
      || !enif_inspect_binary(env, argv[1], &keyfile)
      || !enif_get_string(env, argv[2], password, sizeof(password) - 1, ERL_NIF_LATIN1)) {

        RSA_free(rsa);
	      return enif_make_badarg(env);
  }

  fp = fopen("./priv/priv_key.pem", "r");

  SSLeay_add_all_ciphers();
  rsa = PEM_read_RSAPrivateKey(fp, NULL, NULL, password);

  enif_alloc_binary(RSA_size(rsa), &ret_bin);

  i = RSA_private_decrypt(data_bin.size, data_bin.data,
                         ret_bin.data, rsa, padding);

  ///

  if (i > 0) {
    return enif_make_binary(env,&ret_bin);
  } else {
    enif_release_binary(&ret_bin);
    return enif_make_tuple2(env, atom_error, atom_bad_args);
  }
}

static ErlNifFunc nif_funcs[] = {
  {"rsagen", 1, rsa_generate_key_nif},
  {"encrypt", 2, rsa_encrypt}, //def encrypt(_data, _pub_key) do
  {"decrypt", 3, rsa_decrypt} //def decrypt(_data, _priv_key, _password) do
};

ERL_NIF_INIT(Elixir.RsaKeys, nif_funcs, load, NULL, upgrade, NULL);
