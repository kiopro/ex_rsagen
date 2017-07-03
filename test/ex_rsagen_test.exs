defmodule RsaKeysTest do
  use ExUnit.Case
  doctest RsaKeys

  test "the truth" do
    assert 1 + 1 == 2
  end

  test "test rsagen" do
    password = String.to_char_list("qwerty")
    assert {:ok, _pub, _priv} = RsaKeys.rsagen(password)
  end

  test "test rsagen badargs" do
    assert {:error, :bad_args} == RsaKeys.rsagen(123)
  end

  test "test full test case" do
    password = "12345"
    test_data = "test data for encrypt/decrypt!"

    assert {:ok, priv_key, pub_key} = RsaKeys.generate_keys(password)
    data = RsaKeys.encrypt_data(test_data, pub_key)
    assert test_data == RsaKeys.decrypt_data(data, password, priv_key)
  end

end
