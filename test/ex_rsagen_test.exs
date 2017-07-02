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
end
