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
end
