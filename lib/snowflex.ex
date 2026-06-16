defmodule Snowflex do
  @doc_header """
  Snowflex is an Ecto adapter for [Snowflake](https://www.snowflake.com/) using Snowflake's [SQL API](https://docs.snowflake.com/en/developer-guide/sql-api/reference).
  """
  @readme Path.join([__DIR__, "../README.md"])

  @doc_footer @readme
              |> File.read!()
              |> String.split("<!-- MDOC -->")
              |> Enum.fetch!(1)

  @moduledoc @doc_header <> @doc_footer

  @behaviour Ecto.Adapter
  @behaviour Ecto.Adapter.Queryable
  @behaviour Ecto.Adapter.Schema
  @behaviour Ecto.Adapter.Transaction

  alias Ecto.Adapters.SQL
  alias Ecto.UUID

  @conn __MODULE__.Ecto.Adapter.Connection

  @impl Ecto.Adapter
  defmacro __before_compile__(env) do
    SQL.__before_compile__(:snowflex, env)
  end

  @impl Ecto.Adapter
  def ensure_all_started(config, type) do
    SQL.ensure_all_started(:snowflex, config, type)
  end

  @impl Ecto.Adapter
  def init(config) do
    SQL.init(@conn, :snowflex, config)
  end

  @impl Ecto.Adapter
  def checkout(meta, opts, fun) do
    SQL.checkout(meta, opts, fun)
  end

  @impl Ecto.Adapter
  def checked_out?(meta) do
    SQL.checked_out?(meta)
  end

  @impl Ecto.Adapter
  def loaders(:integer, type), do: [&int_decode/1, type]
  def loaders(:decimal, type), do: [&decimal_decode/1, type]
  def loaders(:float, type), do: [&float_decode/1, type]
  def loaders(:date, type), do: [&date_decode/1, type]
  def loaders(:id, type), do: [&int_decode/1, type]
  def loaders(:time, type), do: [&time_decode/1, type]
  def loaders(:time_usec, type), do: [&time_decode/1, type]
  def loaders(_, type), do: [type]

  @impl Ecto.Adapter
  def dumpers(:binary, type), do: [type, &binary_encode/1]
  def dumpers(_, type), do: [type]

  defp binary_encode(raw), do: {:ok, Base.encode16(raw)}

  defp decimal_decode(nil), do: {:ok, nil}
  defp decimal_decode(dec) when is_binary(dec), do: {:ok, Decimal.new(dec)}
  defp decimal_decode(dec) when is_float(dec), do: {:ok, Decimal.from_float(dec)}

  defp int_decode(nil), do: {:ok, nil}
  defp int_decode(int) when is_binary(int), do: {:ok, String.to_integer(int)}
  defp int_decode(int), do: {:ok, int}

  defp time_decode(nil), do: {:ok, nil}
  defp time_decode(time), do: Time.from_iso8601(time)

  defp float_decode(nil), do: {:ok, nil}
  defp float_decode(float) when is_float(float), do: float
  defp float_decode(%Decimal{} = decimal), do: {:ok, Decimal.to_float(decimal)}

  defp float_decode(float) do
    {val, _} = Float.parse(float)
    {:ok, val}
  end

  defp date_decode(nil), do: {:ok, nil}
  defp date_decode(%Date{} = date), do: {:ok, date}
  defp date_decode(date), do: Date.from_iso8601(date)

  ## Query

  @impl Ecto.Adapter.Queryable
  def prepare(:all, query) do
    {:cache, {System.unique_integer([:positive]), IO.iodata_to_binary(@conn.all(query))}}
  end

  def prepare(:update_all, query) do
    {:cache, {System.unique_integer([:positive]), IO.iodata_to_binary(@conn.update_all(query))}}
  end

  def prepare(:delete_all, query) do
    {:cache, {System.unique_integer([:positive]), IO.iodata_to_binary(@conn.delete_all(query))}}
  end

  @impl Ecto.Adapter.Queryable
  def execute(adapter_meta, query_meta, query, params, opts) do
    SQL.execute(:named, adapter_meta, query_meta, query, params, opts)
  end

  # Streaming uses the shared `Ecto.Adapters.SQL` cursor machinery, which fetches
  # one chunk per `handle_fetch/4` instead of materializing the whole result set.
  # As with every Ecto SQL adapter, the stream must be enumerated inside a
  # `Repo.transaction/2`. Snowflake has no real transactions, so that transaction
  # is a no-op (see `Snowflex.Connection` for the FAKE-transaction details); it
  # exists only to lend the cursor a locked connection.
  @impl Ecto.Adapter.Queryable
  def stream(adapter_meta, query_meta, prepared, params, opts) do
    SQL.stream(adapter_meta, query_meta, prepared, params, opts)
  end

  ## Transaction

  # Snowflake has no real transactions (see `Snowflex.Connection` for the FAKE,
  # no-op transaction callbacks). Implementing this behaviour is what exposes
  # `Repo.transaction/2`, `Repo.transact/2`, and the transaction context that
  # `Repo.stream/2` requires.
  @impl Ecto.Adapter.Transaction
  def transaction(adapter_meta, opts, fun) do
    SQL.transaction(adapter_meta, opts, fun)
  end

  @impl Ecto.Adapter.Transaction
  def in_transaction?(adapter_meta) do
    SQL.in_transaction?(adapter_meta)
  end

  @impl Ecto.Adapter.Transaction
  def rollback(adapter_meta, value) do
    SQL.rollback(adapter_meta, value)
  end

  ## Schema

  @impl Ecto.Adapter.Schema
  def autogenerate(:id), do: nil
  def autogenerate(:embed_id), do: UUID.generate()
  def autogenerate(:binary_id), do: UUID.bingenerate()

  @impl Ecto.Adapter.Schema
  def insert_all(
        adapter_meta,
        schema_meta,
        header,
        rows,
        on_conflict,
        returning,
        placeholders,
        opts
      ) do
    SQL.insert_all(
      adapter_meta,
      schema_meta,
      @conn,
      header,
      rows,
      on_conflict,
      returning,
      placeholders,
      opts
    )
  end

  @impl Ecto.Adapter.Schema
  def insert(adapter_meta, schema_meta, params, on_conflict, returning, opts) do
    %{source: source, prefix: prefix} = schema_meta
    {kind, conflict_params, _} = on_conflict
    {fields, values} = :lists.unzip(params)
    sql = @conn.insert(prefix, source, fields, [fields], on_conflict, returning, [])

    SQL.struct(
      adapter_meta,
      @conn,
      sql,
      :insert,
      source,
      [],
      values ++ conflict_params,
      kind,
      returning,
      opts
    )
  end

  @impl Ecto.Adapter.Schema
  def update(adapter_meta, schema_meta, fields, params, returning, opts) do
    %{source: source, prefix: prefix} = schema_meta
    {fields, field_values} = :lists.unzip(fields)
    filter_values = Keyword.values(params)
    sql = @conn.update(prefix, source, fields, params, returning)

    SQL.struct(
      adapter_meta,
      @conn,
      sql,
      :update,
      source,
      params,
      field_values ++ filter_values,
      :raise,
      returning,
      opts
    )
  end

  @impl Ecto.Adapter.Schema
  def delete(adapter_meta, schema_meta, params, returning, opts) do
    %{source: source, prefix: prefix} = schema_meta
    filter_values = Keyword.values(params)
    sql = @conn.delete(prefix, source, params, returning)

    SQL.struct(
      adapter_meta,
      @conn,
      sql,
      :delete,
      source,
      params,
      filter_values,
      :raise,
      returning,
      opts
    )
  end
end
