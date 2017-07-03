defmodule RsaKeys do
  @on_load :load_nif
  @moduledoc """
  Documentation for RsaKeys.
  """

  @doc """
  Loading nif functions
  """
  def load_nif do
    :erlang.load_nif('./priv/rsagen', 0)
  end

  @doc """
  Nif function for generate rsa keys with des3
  """
  def rsagen(_) do
    exit(:nif_library_not_loaded)
  end

  @doc """
  Nif function for encrypt data with public key
  """
  def encrypt(_data, _key) do
    exit(:nif_library_not_loaded)
  end

  @doc """
  Nif function for decrypt data with private key and password
  """
  def decrypt(_data, _priv_key, _password) do
    exit(:nif_library_not_loaded)
  end

  @doc """
  generate_keys(String // password)

  ## Examples

      iex> RsaKeys.generate_keys("123123")
      {:ok,
        "-----BEGIN RSA PRIVATE KEY-----
        Proc-Type: 4,ENCRYPTED
        DEK-Info: DES-EDE3-CBC,3123FE7FDE3D2D06

        vUI5BtcWw88KE0q.......
        -----END RSA PRIVATE KEY-----
        ",
        "-----BEGIN PUBLIC KEY-----
        MIIBIjANB.......
        -----END PUBLIC KEY-----
        "}

  """

  @spec generate_keys(String) :: {atom, Binary, Binary}
  def generate_keys(password) do
    pwd = String.to_char_list(password)
    RsaKeys.rsagen(pwd)
  end

  @doc """
  Encrypt data with data, public key and save to file
  """
  @spec encrypt_data(Binary, Binary) :: Binary
  def encrypt_data(data, pub_key) do
    RsaKeys.encrypt(data, pub_key)
  end

  @doc """
  Decrypt data with encrypted data, password, private key and save to file
  """
  @spec decrypt_data(Binary, String, Binary) :: Binary
  def decrypt_data(data, password, priv_key) do
    pwd = String.to_char_list(password)
    RsaKeys.decrypt(data, priv_key, pwd)
  end

  @doc """
  Save binary data to priv folder with filename
  """
  @spec save_to_file(Binary, String) :: Binary
  def save_to_file(data, filename) do
    path = Path.absname("./priv/#{filename}")
    {:ok, file} = File.open path, [:write]
    IO.binwrite file, data
    File.close file

    data
  end

end
