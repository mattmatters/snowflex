defmodule Snowflex.Transport.Http do
  @moduledoc """
  REST API transport implementation for Snowflake.
  See: https://docs.snowflake.com/en/developer-guide/sql-api/reference

  ## Configuration Options

  The HTTP transport supports the following configuration options:

  ### Required Options
  * `:account_name` - Your Snowflake account identifier (e.g., "my-org-my-account")
  * `:username` - Your Snowflake username
  * `:private_key_path` - Path to your private key file (PEM format) OR
  * `:private_key_from_string` - Your private key as a string (PEM format)
  * `:public_key_fingerprint` - Fingerprint of your public key

  ### Optional Options
  * `:database` - Default database to use
  * `:schema` - Default schema to use
  * `:warehouse` - Default warehouse to use
  * `:role` - Default role to use
  * `:timeout` - Query timeout in milliseconds (default: 45 seconds)
  * `:token_lifetime` - JWT token lifetime in milliseconds (default: 10 minutes)
  * `:private_key_password` - Password for the private key (if encrypted)
  * `:fetch_token` - Callback function or MFA tuple for custom token retrieval (see below)
  * `:async_poll_interval` - Interval in milliseconds to poll for async execution status (default: 1000)
  * `:max_retries` - Maximum retry attempts for rate limits (default: 3)
  * `:retry_base_delay` - Base delay for exponential backoff in milliseconds (default: 1000)
  * `:retry_max_delay` - Maximum delay between retries in milliseconds (default: 8000)
  * `:connect_options` - Connection options for `Req`, see `Req.new/1` for more details.

  ## Account Name Handling

  The transport automatically handles different Snowflake account name formats for JWT token generation:

  * For global accounts (e.g., "account-123.global.snowflakecomputing.com"):
    - Extracts the account identifier before the first hyphen
    - Example: "account-123" becomes "ACCOUNT"

  * For regional accounts (e.g., "account.us-east-1.snowflakecomputing.com"):
    - Extracts the account identifier before the first dot
    - Example: "account.us-east-1" becomes "ACCOUNT"


  ## Authentication

  The transport supports multiple authentication methods:

  ### JWT Key Pair Authentication (default)
  Uses RSA key pairs to generate JWT tokens. The private key must be in PEM format
  and the public key fingerprint must be registered with Snowflake.

  ### Custom Token Callback (session, OAuth, WIF, PAT)
  For OAuth, Workload Identity Federation (WIF), or Programmatic Access Tokens (PAT),
  use the `:fetch_token` option to provide a callback that returns the token.

  The callback must return `{:ok, {token, token_type, expires_at}}` where:
  * `token` - The bearer token string
  * `token_type` - One of `:jwt`, `:oauth`, or `:pat`
  * `expires_at` - Unix timestamp in seconds when the token expires

  When using `:fetch_token`, the `:private_key_path`, `:private_key_from_string`,
  and `:public_key_fingerprint` options are not required.

  ```elixir
  # Using an anonymous function
  config :my_app, MyApp.Repo,
    account_name: "my-org-my-account",
    username: "my_service_user",
    fetch_token: fn ->
      # Your custom logic to get a token (e.g., WIF with AWS role chaining)
      {:ok, {token, :oauth, expires_at}}
    end

  # Using an MFA tuple
  config :my_app, MyApp.Repo,
    account_name: "my-org-my-account",
    username: "my_service_user",
    fetch_token: {MyApp.Auth, :get_snowflake_token, []}
  ```

  ## Private Key Configuration

  Snowflex supports two ways to provide your private key for authentication:

  ### 1. File Path (traditional method)
  ```elixir
  config :my_app, MyApp.Repo,
    # ... other options ...
    private_key_path: "/path/to/your/private_key.pem"
  ```

  ### 2. String (inline method)
  ```elixir
  config :my_app, MyApp.Repo,
    # ... other options ...
    private_key_from_string: System.get_env("SNOWFLAKE_PRIVATE_KEY") || \"\"\"
    -----BEGIN PRIVATE KEY-----
    MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC...
    -----END PRIVATE KEY-----
    \"\"\"
  ```

  **Important notes:**
  - You must provide either `private_key_path` OR `private_key_from_string`, not both
  - Both options accept PEM format private keys
  - The string method is useful when deploying to environments where file system access is restricted or when storing keys in environment variables/secrets management systems

  ## Example Configuration

  ```elixir
  config :my_app, MyApp.Repo,
    adapter: Snowflex,
    transport: Snowflex.Transport.Http,
    account_name: "my-org-my-account",
    username: "my_user",
    private_key_path: "/path/to/key.pem",
    # OR alternatively use private_key_from_string instead of private_key_path:
    # private_key_from_string: "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----",
    public_key_fingerprint: "abc123...",
    database: "MY_DB",
    schema: "MY_SCHEMA",
    warehouse: "MY_WH",
    role: "MY_ROLE",
    timeout: :timer.seconds(30),
    token_lifetime: :timer.minutes(15),
    # Retry configuration
    max_retries: 3,
    retry_base_delay: :timer.seconds(1),
    retry_max_delay: :timer.seconds(8)
  ```
  """
  @behaviour Snowflex.Transport
  use GenServer

  alias JOSE.JWK
  alias JOSE.JWS
  alias JOSE.JWT
  alias Snowflex.Error
  alias Snowflex.Result

  require Logger

  @default_token_lifetime :timer.minutes(10)
  @default_timeout :timer.seconds(45)
  defmodule State do
    @moduledoc false
    @derive {Inspect, except: [:private_key, :private_key_password]}

    defstruct [
      :account_name,
      :username,
      :private_key,
      :private_key_password,
      :timeout,
      :fetch_token,
      :token,
      :token_type,
      :token_expires_at,
      :token_lifetime,
      :current_statement,
      :current_partition,
      :database,
      :schema,
      :warehouse,
      :role,
      :public_key_fingerprint,
      :result_metadata,
      :async_poll_interval,
      :max_retries,
      :retry_base_delay,
      :retry_max_delay,
      :connect_options
    ]

    @type t :: %__MODULE__{
            account_name: String.t(),
            username: String.t(),
            private_key: String.t(),
            private_key_password: String.t() | nil,
            timeout: integer(),
            fetch_token: function() | mfa() | nil,
            token: String.t() | nil,
            token_expires_at: non_neg_integer() | nil,
            token_lifetime: integer(),
            token_type: :jwt | :wif | nil,
            current_statement: String.t() | nil,
            current_partition: integer() | nil,
            database: String.t() | nil,
            schema: String.t() | nil,
            warehouse: String.t() | nil,
            role: String.t() | nil,
            public_key_fingerprint: String.t() | nil,
            result_metadata: map() | nil,
            async_poll_interval: non_neg_integer(),
            max_retries: non_neg_integer(),
            retry_base_delay: non_neg_integer(),
            retry_max_delay: non_neg_integer(),
            connect_options: Keyword.t()
          }
  end

  @impl Snowflex.Transport
  # HTTP transport does not care about connection state or sessions, we do not need ping
  def ping(_pid), do: {:ok, %Result{}}

  @impl Snowflex.Transport
  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts)
  end

  @impl Snowflex.Transport
  def execute_statement(pid, statement, params, opts) do
    opts = add_default_timeout(opts)

    try do
      GenServer.call(pid, {:execute, statement, params, opts}, opts[:timeout])
    catch
      :exit, {:timeout, _} ->
        {:error, Error.exception("#{statement} timed out after #{inspect(opts[:timeout])}")}

      :exit, reason ->
        {:error, Error.exception("#{statement} failed due to #{inspect(reason)}")}
    end
  end

  @impl Snowflex.Transport
  def declare(pid, statement, params, opts) do
    opts = add_default_timeout(opts)
    GenServer.call(pid, {:declare, statement, params, opts}, opts[:timeout])
  end

  @impl Snowflex.Transport
  def fetch(pid, cursor, opts) do
    opts = add_default_timeout(opts)
    GenServer.call(pid, {:fetch, cursor, opts}, opts[:timeout])
  end

  @impl Snowflex.Transport
  def disconnect(pid) do
    if Process.alive?(pid) do
      Process.exit(pid, :normal)
    end

    :ok
  end

  @doc """
  Returns the current `t:Req.Request` for the transport.

  Useful when you need to execute an arbitrary API request against Snowflake's REST API.
  """
  @spec client(GenServer.server()) :: Req.Request.t()
  def client(pid) do
    GenServer.call(pid, :client)
  end

  defp add_default_timeout(opts) do
    Keyword.put_new(opts, :timeout, :timer.seconds(45))
  end

  # GenServer callbacks

  @impl GenServer
  def init(opts) do
    with {:ok, validated_opts, private_key} <- validate_and_read_private_key(opts),
         {:ok, state} <- init_state(validated_opts, private_key) do
      check_connection(state)
    end
  end

  def handle_call(:client, _from, state) do
    {:reply, build_req_client(state), state}
  end

  @impl GenServer
  def handle_call({:execute, statement, params, opts}, _from, state) do
    with {:ok, status, body} <- fetch_statement(state, statement, params, opts),
         #  After 45 seconds, Snowflake will return a 202 status code and a body with a statementHandle
         #  We need to poll for the result set
         {:ok, body} <- await_async_execution(state, status, body),
         # Once we have the initial body, we might need to make additional requests
         # to gather the partitions
         # We will reduce over the partitions to get the full result set
         {:ok, raw_result} <- gather_results(state, body, opts) do
      # And then format it for return
      result = format_response_body(raw_result)
      {:reply, {:ok, result}, state}
    else
      {:error, error} -> {:reply, {:error, error}, state}
    end
  end

  # v1 API: declare stores query ID and chunk info for streaming
  def handle_call({:declare, statement, params, opts}, _from, state) do
    case fetch_statement(state, statement, params, opts) do
      {:ok, _status, %{"queryId" => query_id, "rowtype" => rowtype, "chunks" => chunks} = data}
      when is_list(chunks) ->
        chunk_count = length(chunks)

        {:reply, {:ok, chunk_count},
         %{
           state
           | current_statement: query_id,
             current_partition: 0,
             result_metadata: %{
               "rowType" => rowtype,
               "chunks" => chunks,
               "chunkHeaders" => data["chunkHeaders"]
             }
         }}

      {:ok, _status, %{"queryId" => query_id, "rowtype" => rowtype}} ->
        # No chunks, single result set
        {:reply, {:ok, 0},
         %{
           state
           | current_statement: query_id,
             current_partition: 0,
             result_metadata: %{"rowType" => rowtype}
         }}

      {:error, error} ->
        {:reply, {:error, error}, state}
    end
  end

  # v1 API: fetch chunks from S3
  def handle_call(
        {:fetch, max_partition, _opts},
        _from,
        %{
          current_partition: current_partition,
          result_metadata: %{"chunks" => chunks, "chunkHeaders" => headers} = metadata
        } = state
      )
      when current_partition <= max_partition and is_list(chunks) do
    chunk = Enum.at(chunks, current_partition)
    key = headers["x-amz-server-side-encryption-customer-key"]
    md5 = headers["x-amz-server-side-encryption-customer-key-md5"]

    case fetch_s3_chunk(chunk, key, md5) do
      {:ok, rows} ->
        rowtype = metadata["rowType"]
        mapped_rows = map_rows(rows, rowtype)

        result = %Result{
          columns: Enum.map(rowtype, & &1["name"]),
          rows: mapped_rows,
          num_rows: length(mapped_rows)
        }

        {:reply, {:ok, result}, %{state | current_partition: current_partition + 1}}

      {:error, error} ->
        {:reply, {:error, error}, state}
    end
  end

  # No chunks or no more partitions
  def handle_call(
        {:fetch, _max_partition, _opts},
        _from,
        %{current_statement: current_statement} = state
      )
      when is_binary(current_statement) and byte_size(current_statement) > 0 do
    {:reply, {:halt, %Result{}}, state}
  end

  def handle_call({:fetch, _max_partition, _opts}, _from, state) do
    {:reply, {:error, %Error{message: "No active statement"}}, state}
  end

  ## Query helpers

  # v1 API async query response (code 333334 means async execution started)
  defp await_async_execution(state, 200, %{"queryId" => query_id} = body)
       when not is_map_key(body, "rowtype") do
    poll_query_status(state, query_id)
  end

  defp await_async_execution(_state, _status, body), do: {:ok, body}

  defp poll_query_status(state, query_id) do
    url = "/monitoring/queries/#{query_id}"
    req_client = build_req_client(state)

    case Req.get(req_client, url: url, receive_timeout: state.timeout) do
      {:ok, %{status: 200, body: %{"data" => %{"queries" => [%{"status" => status}]}}}}
      when status in ["RUNNING", "QUEUED", "RESUMING_WAREHOUSE"] ->
        Process.sleep(state.async_poll_interval)
        poll_query_status(state, query_id)

      {:ok, %{status: 200, body: %{"data" => %{"queries" => [%{"status" => "SUCCESS"}]}}}} ->
        fetch_query_result(state, query_id)

      {:ok,
       %{
         status: 200,
         body: %{"data" => %{"queries" => [%{"status" => status, "errorMessage" => error}]}}
       }} ->
        {:error, %Error{message: error, code: status}}

      {:ok, %{status: 200, body: %{"data" => %{"queries" => []}}}} ->
        # Query not found yet, keep polling
        Process.sleep(state.async_poll_interval)
        poll_query_status(state, query_id)

      {:ok, %{body: %{"message" => message}}} ->
        {:error, %Error{message: message}}

      {:error, err} ->
        {:error, %Error{message: inspect(err)}}
    end
  end

  defp fetch_query_result(state, query_id) do
    url = "/queries/#{query_id}/result"
    req_client = build_req_client(state)

    case Req.get(req_client, url: url, receive_timeout: state.timeout) do
      {:ok, %{status: 200, body: %{"success" => true, "data" => data}}} ->
        {:ok, data}

      {:ok, %{body: %{"message" => message}}} ->
        {:error, %Error{message: message}}

      {:error, err} ->
        {:error, %Error{message: inspect(err)}}
    end
  end

  # v1 API: Handle responses with S3 chunks (large result sets)
  defp gather_results(
         _state,
         %{
           "chunks" => chunks,
           "chunkHeaders" => %{
             "x-amz-server-side-encryption-customer-key" => key,
             "x-amz-server-side-encryption-customer-key-md5" => md5
           },
           "rowset" => initial_rowset,
           "rowtype" => _rowtype
         } = body,
         opts
       )
       when is_list(chunks) and length(chunks) > 0 do
    max_concurrency = System.schedulers_online()
    extended_timeout = opts[:timeout] + :timer.seconds(30)

    # Fetch chunks from S3 in parallel
    chunk_rows =
      Task.Supervisor.async_stream_nolink(
        Snowflex.TaskSupervisor,
        chunks,
        fn chunk -> fetch_s3_chunk(chunk, key, md5) end,
        max_concurrency: max_concurrency,
        ordered: true,
        timeout: extended_timeout,
        on_timeout: :kill_task
      )
      |> Enum.reduce_while({:ok, []}, fn
        {:ok, {:ok, rows}}, {:ok, acc} ->
          {:cont, {:ok, acc ++ rows}}

        {:ok, {:error, error}}, _acc ->
          {:halt, {:error, error}}

        {:exit, reason}, _acc ->
          {:halt, {:error, %Error{message: "Chunk download failed: #{inspect(reason)}"}}}
      end)

    case chunk_rows do
      {:ok, all_chunk_rows} ->
        merged_rowset = initial_rowset ++ all_chunk_rows
        {:ok, Map.put(body, "rowset", merged_rowset)}

      {:error, error} ->
        {:error, error}
    end
  end

  # No chunks, return as-is
  defp gather_results(_state, body, _opts) do
    {:ok, body}
  end

  defp fetch_s3_chunk(%{"url" => url}, encryption_key, encryption_key_md5) do
    headers = [
      {"Accept", "application/snowflake"},
      {"x-amz-server-side-encryption-customer-algorithm", "AES256"},
      {"x-amz-server-side-encryption-customer-key", encryption_key},
      {"x-amz-server-side-encryption-customer-key-md5", encryption_key_md5}
    ]

    case Req.get(url: url, headers: headers, receive_timeout: 180_000) do
      {:ok, %{status: 200, body: body}} when is_list(body) ->
        {:ok, body}

      {:ok, %{status: 200, body: body}} when is_binary(body) ->
        # Body might be JSON string
        case JSON.decode(body) do
          {:ok, rows} when is_list(rows) -> {:ok, rows}
          _ -> {:error, %Error{message: "Failed to decode chunk"}}
        end

      {:ok, %{status: status, body: body}} ->
        {:error, %Error{message: "Chunk download failed: HTTP #{status}: #{inspect(body)}"}}

      {:error, err} ->
        {:error, %Error{message: "Chunk download failed: #{inspect(err)}"}}
    end
  end

  # Init/Config Helpers
  defp validate_and_read_private_key(opts) do
    with {:ok, opts} <- validate_required_opts(opts),
         {:ok, opts, private_key} <- validate_and_read_private_key_opts(opts) do
      {:ok, opts, private_key}
    else
      {:stop, error} -> {:stop, error}
    end
  end

  defp validate_required_opts(opts) do
    has_fetch_token = Keyword.has_key?(opts, :fetch_token)

    required_keys =
      if has_fetch_token do
        [:account_name, :username]
      else
        [:account_name, :username, :public_key_fingerprint]
      end

    Enum.reduce_while(
      required_keys,
      {:ok, opts},
      fn
        key, validated_opts ->
          case Keyword.fetch(opts, key) do
            {:ok, value} when is_binary(value) and byte_size(value) > 0 ->
              {:cont, validated_opts}

            _any ->
              {:halt, {:stop, %Error{message: "Missing required option: #{key}"}}}
          end
      end
    )
  end

  defp validate_and_read_private_key_opts(opts) do
    private_key_path = Keyword.get(opts, :private_key_path)
    private_key_from_string = Keyword.get(opts, :private_key_from_string)
    has_fetch_token = Keyword.has_key?(opts, :fetch_token)

    case {private_key_path, private_key_from_string, has_fetch_token} do
      {path, nil, _} when is_binary(path) and byte_size(path) > 0 ->
        read_private_key_from_file(opts, path)

      {nil, key, _} when is_binary(key) and byte_size(key) > 0 ->
        {:ok, opts, key}

      {path, key, _}
      when is_binary(path) and byte_size(path) > 0 and is_binary(key) and byte_size(key) > 0 ->
        {:stop,
         %Error{
           message: "Both :private_key_path and :private_key_from_string provided. Use only one."
         }}

      {_, _, true} ->
        # fetch_token provided, private key not required
        {:ok, opts, nil}

      {_, _, false} ->
        {:stop,
         %Error{
           message: "Either :private_key_path or :private_key_from_string must be provided"
         }}
    end
  end

  defp read_private_key_from_file(opts, path) do
    case File.read(path) do
      {:ok, key} ->
        {:ok, opts, key}

      {:error, reason} ->
        {:stop, %Error{message: "Failed to read private key from path: #{inspect(reason)}"}}
    end
  end

  defp init_state(validated_opts, private_key) do
    {:ok,
     %State{
       account_name: Keyword.fetch!(validated_opts, :account_name),
       username: Keyword.fetch!(validated_opts, :username),
       public_key_fingerprint: Keyword.get(validated_opts, :public_key_fingerprint),
       private_key: private_key,
       private_key_password: Keyword.get(validated_opts, :private_key_password, ~c""),
       current_statement: nil,
       timeout: Keyword.get(validated_opts, :timeout, @default_timeout),
       token_lifetime: Keyword.get(validated_opts, :token_lifetime, @default_token_lifetime),
       fetch_token: Keyword.get(validated_opts, :fetch_token),
       token_expires_at: nil,
       database: Keyword.get(validated_opts, :database),
       schema: Keyword.get(validated_opts, :schema),
       warehouse: Keyword.get(validated_opts, :warehouse),
       role: Keyword.get(validated_opts, :role),
       async_poll_interval: Keyword.get(validated_opts, :async_poll_interval, 1000),
       max_retries: Keyword.get(validated_opts, :max_retries, 3),
       retry_base_delay: Keyword.get(validated_opts, :retry_base_delay, 1000),
       retry_max_delay: Keyword.get(validated_opts, :retry_max_delay, 8000),
       connect_options: Keyword.get(validated_opts, :connect_options, [])
     }}
  end

  defp check_connection(state) do
    state = maybe_refresh_token!(state)

    case fetch_statement(state, "SELECT 1", %{}, timeout: state.timeout) do
      {:ok, _status, _body} ->
        {:ok, state}

      {:error, error} ->
        {:stop, error}
    end
  end

  # Token helpers

  defp generate_token(state) do
    now = System.system_time(:second)
    # Backwards compatibility(ish), this was mistakenly ms when it should be seconds
    expires_at = now + Integer.floor_div(state.token_lifetime, 1000)

    account_id = prepare_account_name_for_jwt(state.account_name)
    username = String.upcase(state.username)

    [pem_entry] = :public_key.pem_decode(state.private_key)
    private_key = :public_key.pem_entry_decode(pem_entry, state.private_key_password)
    jwk = JWK.from_key(private_key)

    claims = %{
      "iss" => "#{account_id}.#{username}.SHA256:#{state.public_key_fingerprint}",
      "sub" => "#{account_id}.#{username}",
      "iat" => now,
      "exp" => expires_at
    }

    jws = %{"alg" => "RS256"}
    jwt = JWT.sign(jwk, jws, claims)
    {_, token} = JWS.compact(jwt)

    {:ok, {token, :jwt, expires_at}}
  end

  defp prepare_account_name_for_jwt(raw_account) do
    account =
      if String.contains?(raw_account, ".global") do
        case String.split(raw_account, "-", parts: 2) do
          [account_id | _] -> account_id
          _ -> raw_account
        end
      else
        case String.split(raw_account, ".", parts: 2) do
          [account_id | _] -> account_id
          _ -> raw_account
        end
      end

    String.upcase(account)
  end

  # HTTP

  defp build_req_client(state) do
    base_url = "https://#{state.account_name}.snowflakecomputing.com"

    Req.new(
      base_url: base_url,
      headers: [
        {"Authorization", "Snowflake Token=\"#{state.token}\""},
        {"Content-Type", "application/json"},
        {"Accept", "application/snowflake"},
        {"User-Agent", "snowflex/#{snowflex_version()}"}
      ],
      retry: :safe_transient,
      retry_delay: fn attempt ->
        calculate_backoff_delay(attempt, state.retry_base_delay, state.retry_max_delay)
      end,
      max_retries: state.max_retries,
      connect_options: state.connect_options
    )
  end

  defp snowflex_version do
    Application.spec(:snowflex)[:vsn]
  end

  defp calculate_backoff_delay(attempt, base_delay, max_delay) do
    # Exponential backoff with jitter
    # attempt starts at 0, so we use attempt for the power calculation
    exponential_delay = base_delay * :math.pow(2, attempt)
    capped_delay = min(exponential_delay, max_delay)
    jitter = :rand.uniform() * 0.1 * capped_delay
    trunc(capped_delay + jitter)
  end

  defp format_response_body(body) when is_list(body) do
    Enum.map(body, fn {:ok, statement_body} -> format_response_body(statement_body) end)
  end

  # v1 API response format
  defp format_response_body(%{"rowtype" => rowtype, "rowset" => rowset} = body) do
    columns = Enum.map(rowtype, & &1["name"])
    rows = map_rows(rowset, rowtype)

    result_v1(body, %{
      columns: columns,
      rows: rows,
      num_rows: body["total"] || length(rows),
      metadata: %{"rowType" => rowtype}
    })
  end

  # v1 API response with no rows (DDL, DML)
  defp format_response_body(%{"rowtype" => rowtype, "total" => total} = body) do
    columns = Enum.map(rowtype, & &1["name"])

    result_v1(body, %{
      columns: columns,
      rows: [],
      num_rows: total
    })
  end

  # Fallback for other responses
  defp format_response_body(body) do
    result_v1(body, %{messages: [body["message"] || "Query executed successfully"]})
  end

  defp result_v1(body, attrs) do
    %{
      query_id: body["queryId"],
      request_id: nil,
      sql_state: body["sqlState"]
    }
    |> Map.merge(attrs)
    |> then(&struct!(Result, &1))
  end

  # Map row values based on column types
  defp map_rows(rowset, rowtype) do
    Enum.map(rowset, fn row ->
      row
      |> Enum.zip(rowtype)
      |> Enum.map(fn {value, col} -> map_value(value, col) end)
    end)
  end

  defp map_value(nil, _col), do: nil
  defp map_value(value, %{"type" => "fixed", "scale" => 0}), do: parse_integer(value)
  defp map_value(value, %{"type" => "fixed"}), do: parse_decimal(value)
  defp map_value(value, %{"type" => "real"}), do: parse_float(value)
  defp map_value(value, %{"type" => "boolean"}), do: value == "true" or value == true
  defp map_value(value, %{"type" => "date"}), do: value
  defp map_value(value, %{"type" => "time"}), do: value
  # TODO I believe I need to handle these here instead of the other type spot
  defp map_value(value, %{"type" => "timestamp_ntz"}), do: value
  defp map_value(value, %{"type" => "timestamp_tz"}), do: value
  defp map_value(value, %{"type" => "timestamp_ltz"}), do: value
  defp map_value(value, _col), do: value

  defp parse_integer(value) when is_integer(value), do: value
  defp parse_integer(value) when is_binary(value), do: String.to_integer(value)
  defp parse_integer(value), do: value

  defp parse_float(value) when is_float(value), do: value

  defp parse_float(value) when is_binary(value) do
    {val, _} = Float.parse(value)
    val
  end

  defp parse_float(value), do: value

  defp parse_decimal(value) when is_binary(value) do
    case Decimal.parse(value) do
      {decimal, ""} -> decimal
      _ -> value
    end
  end

  defp parse_decimal(value), do: value

  # HTTP Calls

  defp fetch_statement(state, statement, params, opts) do
    req_body = %{
      sqlText: statement,
      sequenceId: 0,
      bindings: params_to_bindings_v1(params),
      bindStage: nil,
      describeOnly: false,
      parameters: request_params(state, opts),
      describedJobId: nil,
      isInternal: false,
      asyncExec: false
    }

    request_id = generate_uuid()
    url = "/queries/v1/query-request?requestId=#{request_id}"

    req_client = build_req_client(state)

    case Req.post(req_client, url: url, json: req_body, receive_timeout: opts[:timeout]) do
      {:ok, %{status: 200, body: %{"success" => true, "data" => data}}} ->
        {:ok, 200, data}

      {:ok, %{body: %{"code" => code, "message" => message, "data" => data}}} ->
        {:error, %Error{message: message, code: code, metadata: %{query_id: data["queryId"]}}}

      {:ok, %{body: %{"code" => code, "message" => message}}} ->
        {:error, %Error{message: message, code: code}}

      {:ok, %{status: status, body: body}} ->
        {:error, %Error{message: "HTTP #{status}: #{inspect(body)}", code: to_string(status)}}

      {:error, exception} ->
        {:error, %Error{message: inspect(exception), code: "HTTP_ERROR"}}
    end
  end

  defp generate_uuid do
    <<a::32, b::16, c::16, d::16, e::48>> = :crypto.strong_rand_bytes(16)

    <<a::32, b::16, 4::4, c::12, 2::2, d::14, e::48>>
    |> Base.encode16(case: :lower)
    |> String.replace(~r/(.{8})(.{4})(.{4})(.{4})(.{12})/, "\\1-\\2-\\3-\\4-\\5")
  end

  defp params_to_bindings_v1(params) when map_size(params) == 0, do: nil
  defp params_to_bindings_v1(params) when params == %{}, do: nil

  defp params_to_bindings_v1(params) do
    params
    |> Enum.with_index(1)
    |> Map.new(fn {value, index} ->
      {"#{index}", value}
    end)
  end

  defp maybe_refresh_token!(state) do
    now = :os.system_time(:second)

    case state do
      %{token: token, token_type: token_type, token_expires_at: expires_at}
      when is_binary(token) and not is_nil(token_type) and expires_at > now ->
        state

      %{fetch_token: cb} when is_function(cb, 0) ->
        {:ok, {token, token_type, expires}} = cb.()
        %{state | token: token, token_type: token_type, token_expires_at: expires}

      %{fetch_token: {mod, fun, args}} ->
        {:ok, {token, token_type, expires}} = apply(mod, fun, args)
        %{state | token: token, token_type: token_type, token_expires_at: expires}

      _ ->
        {:ok, {token, token_type, expires}} = generate_token(state)
        %{state | token: token, token_type: token_type, token_expires_at: expires}
    end
  end

  @default_request_params %{
    "TIME_OUTPUT_FORMAT" => "HH24:MI:SS.FF",
    "TIMESTAMP_OUTPUT_FORMAT" => "YYYY-MM-DDTHH24:MI:SS.FFTZH:TZM",
    "TIMESTAMP_NTZ_OUTPUT_FORMAT" => "YYYY-MM-DDTHH24:MI:SS.FF",
    "DATE_OUTPUT_FORMAT" => "YYYY-MM-DD",
    "MULTI_STATEMENT_COUNT" => "0"
  }

  defp request_params(_state, opts) do
    case Keyword.get(opts, :query_tag) do
      tag when is_binary(tag) ->
        Map.put(@default_request_params, "QUERY_TAG", tag)

      _any ->
        @default_request_params
    end
  end
end
