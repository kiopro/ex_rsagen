defmodule Mix.Tasks.Compile.RsaKeys do
  def run(_args) do
    {result, _errcode} = System.cmd("make", [])
    IO.binwrite(result)
  end
end

defmodule RsaKeys.Mixfile do
  use Mix.Project

  def project do
    [app: :RsaKeys,
     compilers: [:RsaKeys] ++ Mix.compilers,
     version: "0.1.0",
     elixir: "~> 1.4",
     build_embedded: Mix.env == :prod,
     start_permanent: Mix.env == :prod,
     description: description(),
     package: package(),
     deps: deps()]
  end

  # Configuration for the OTP application
  def application do
    # Specify extra applications you'll use from Erlang/Elixir
    [applications: [:logger, :kernel, :stdlib, :crypto]]
  end

  defp deps do
    [{:earmark, "~> 0.1", only: :dev},
    {:ex_doc, "~> 0.11", only: :dev}]
  end

  defp description do
    """
    Crypto module with NIF's for generate RSA keys with DES3 + encrypt/decrypt data
    """
  end

  defp package do
    [
      name: "ex_rsagen",
      files: ["Makefile", "lib", "c_src", "mix.exs", "README*"],
      maintainers: ["kiopro"],
      licenses: ["MIT"],
      links: %{"Github" => "https://github.com/kiopro/ex_rsagen"}]
  end
end
