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

  # ## Examples
  #
  #     iex> RsaKeys.generate_keys("123123")
  #     {:ok,
  #       "-----BEGIN RSA PRIVATE KEY-----
  #       Proc-Type: 4,ENCRYPTED
  #       DEK-Info: DES-EDE3-CBC,3123FE7FDE3D2D06
  #
  #       vUI5BtcWw88KE0q.......
  #       -----END RSA PRIVATE KEY-----
  #       ",
  #       "-----BEGIN PUBLIC KEY-----
  #       MIIBIjANB.......
  #       -----END PUBLIC KEY-----
  #       "}

  """

  @spec generate_keys(String.t) :: {atom, Binary.t, Binary.t}
  def generate_keys(password) do
    pwd = String.to_char_list(password)
    {:ok, priv_key, pub_key} = RsaKeys.rsagen(pwd)

    File.write("./priv/priv_key.pem", priv_key, [:binary])
    File.write("./priv/pub_key.der", pub_key, [:binary])

    {:ok, priv_key, pub_key}
  end

  @doc """
  Get public key from file
  """
  @spec pubkey() :: Binary.t
  def pubkey do
    File.read!("./priv/pub_key.der")
  end

  @doc """
  Get private key from file
  """
  @spec privkey() :: Binary.t
  def privkey do
    File.read!("./priv/priv_key.pem")
  end

  @doc """
  Encrypt data with data, public key and save to file
  """
  @spec encrypt_data(Binary.t, Binary.t) :: Binary.t
  def encrypt_data(data, pub_key \\ pubkey()) do
    RsaKeys.encrypt(data, pub_key)
    |> save_to_file("encrypted.data")
  end

  @doc """
  Decrypt data with encrypted data, password, private key and save to file
  """
  @spec decrypt_data(Binary.t, String.t, Binary.t) :: Binary.t
  def decrypt_data(data, password, priv_key \\ privkey()) do
    pwd = String.to_char_list(password)
    RsaKeys.decrypt(data, priv_key, pwd)
    |> save_to_file("decrypted.data")
  end

  @doc """
  Save binary data to priv folder with filename
  """
  @spec save_to_file(Binary.t, String.t) :: Binary.t
  def save_to_file(data, filename) do
    path = Path.absname("./priv/#{filename}")
    {:ok, file} = File.open path, [:write]
    IO.binwrite file, data
    File.close file

    data
  end

end
