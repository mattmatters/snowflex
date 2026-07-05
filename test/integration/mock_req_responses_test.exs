defmodule Snowflex.MockReqResponsesTest do
  use ExUnit.Case, async: false

  import Req.Test, only: [set_req_test_to_shared: 1]
  import ExUnit.CaptureLog

  alias Plug.Conn
  alias Req.Test, as: ReqTest

  require Logger

  setup :set_req_test_to_shared

  defmodule TestSnowflakeRepo do
    use Ecto.Repo,
      otp_app: :snowflex,
      adapter: Snowflex
  end

  describe "compressed chunks" do
    setup do
      private_key_path = Path.expand("../fixtures/fake_private_key.pem", __DIR__)

      ReqTest.stub(MockHttp, fn
        %{method: "GET", host: "chunks.example.test"} = conn ->
          conn
          |> Conn.put_resp_content_type("application/snowflake")
          |> Conn.put_resp_header("content-encoding", "gzip")
          |> Conn.send_resp(200, :zlib.gzip(~s(["42","decoded"],["43","still decoded"])))

        conn ->
          statement =
            conn
            |> ReqTest.raw_body()
            |> IO.iodata_to_binary()
            |> Jason.decode!()
            |> Map.get("sqlText")

          case statement do
            "SELECT 1" ->
              ReqTest.json(conn, %{"success" => true, "data" => %{}})

            "SELECT * FROM CHUNKED_ROWS" ->
              ReqTest.json(conn, %{
                "success" => true,
                "data" => %{
                  "queryId" => "01b7e043-0206-7a43-0008-8b8300073d86",
                  "rowtype" => [
                    %{"name" => "ID", "type" => "FIXED", "scale" => 0},
                    %{"name" => "NAME", "type" => "TEXT"}
                  ],
                  "rowset" => [],
                  "chunks" => [%{"url" => "https://chunks.example.test/chunk-1"}],
                  "chunkHeaders" => %{},
                  "total" => 2
                }
              })
          end
      end)

      Req.default_options(plug: {Req.Test, MockHttp})

      start_link_supervised!(
        {TestSnowflakeRepo,
         [
           account_name: "test_acc",
           username: "test_usr",
           private_key_path: private_key_path,
           public_key_fingerprint:
             "4dfd2c71b73c0c5a600c5e96004ca52204dfd74632e8e53738770538f7b8af5c",
           role: "fake_role",
           warehouse: "fake_warehouse"
         ]}
      )

      :ok
    end

    test "decodes gzip-compressed chunk responses" do
      result = TestSnowflakeRepo.query!("SELECT * FROM CHUNKED_ROWS")

      assert result.columns == ["ID", "NAME"]
      assert result.rows == [[42, "decoded"], [43, "still decoded"]]
      assert result.num_rows == 2
    end
  end

  describe "async query execution while streaming" do
    @async_query_id "01c57ef7-0106-728c-000a-ce2e019c4fba"

    setup do
      private_key_path = Path.expand("../fixtures/fake_private_key.pem", __DIR__)

      # A slow query returns an async handle (queryId + getResultUrl, no rowtype)
      # instead of an inline result set. declare/4 must poll it to completion before
      # streaming, the same way execute/4 does, or the cursor path CaseClauseErrors.
      ReqTest.stub(MockHttp, fn conn ->
        case {conn.method, conn.request_path} do
          # Poll: query finished successfully.
          {"GET", "/monitoring/queries/" <> _id} ->
            ReqTest.json(conn, %{"data" => %{"queries" => [%{"status" => "SUCCESS"}]}})

          # Result fetch: the real rows, now that the query is done.
          {"GET", "/queries/" <> _rest} ->
            ReqTest.json(conn, %{
              "success" => true,
              "data" => %{
                "queryId" => @async_query_id,
                "rowtype" => [%{"name" => "GREETING", "type" => "TEXT"}],
                "rowset" => [["hello"], ["world"]],
                "total" => 2
              }
            })

          {"POST", _path} ->
            statement =
              conn
              |> ReqTest.raw_body()
              |> IO.iodata_to_binary()
              |> Jason.decode!()
              |> Map.get("sqlText")

            case statement do
              "SELECT 1" ->
                ReqTest.json(conn, %{"success" => true, "data" => %{}})

              _ ->
                ReqTest.json(conn, %{
                  "success" => true,
                  "data" => %{
                    "queryId" => @async_query_id,
                    "getResultUrl" => "/queries/#{@async_query_id}/result",
                    "progressDesc" => nil,
                    "queryAbortsAfterSecs" => 300
                  }
                })
            end
        end
      end)

      Req.default_options(plug: {Req.Test, MockHttp})

      start_link_supervised!(
        {TestSnowflakeRepo,
         [
           account_name: "test_acc",
           username: "test_usr",
           private_key_path: private_key_path,
           public_key_fingerprint:
             "4dfd2c71b73c0c5a600c5e96004ca52204dfd74632e8e53738770538f7b8af5c",
           role: "fake_role",
           warehouse: "fake_warehouse"
         ]}
      )

      :ok
    end

    test "streaming resolves an async result handle" do
      {:ok, rows} =
        TestSnowflakeRepo.transaction(fn ->
          TestSnowflakeRepo
          |> Ecto.Adapters.SQL.stream("SELECT * FROM SLOW_TABLE")
          |> Enum.flat_map(& &1.rows)
        end)

      assert rows == [["hello"], ["world"]]
    end
  end

  describe "Error Handling for Req raised errors" do
    setup do
      # Configure Logger to accept Snowflex metadata keys
      Logger.configure_backend(:console,
        metadata: [
          :snowflex_account_name,
          :snowflex_username,
          :snowflex_warehouse,
          :snowflex_role,
          :snowflex_database,
          :snowflex_schema,
          :snowflex_query_id,
          :snowflex_statement
        ]
      )

      private_key_path = Path.join(File.cwd!(), "test/fixtures/fake_private_key.pem")

      # The transport sends the statement as `sqlText` in the JSON body (only
      # `requestId` is a query param), so dispatch on the decoded body.
      ReqTest.stub(MockHttp, fn conn ->
        {:ok, raw_body, conn} = Conn.read_body(conn)
        statement = raw_body |> Jason.decode!() |> Map.get("sqlText")

        case statement do
          "SELECT 1" ->
            # Health check performed during connect/1 — must look like a successful
            # query (`%{"success" => true, "data" => ...}`) or the connection never
            # establishes and queries die in the pool checkout queue.
            ReqTest.json(conn, %{"success" => true, "data" => %{}})

          _ ->
            # Error response, shaped like Snowflake's: code/message plus a `data`
            # object carrying the queryId the transport surfaces as query metadata.
            conn
            |> Conn.put_resp_content_type("application/json")
            |> Conn.send_resp(
              529,
              Jason.encode!(%{
                "code" => "529",
                "message" => "Server too busy. Please retry.",
                "data" => %{"queryId" => "01b7e043-0206-7a43-0008-8b8300073d86"}
              })
            )
        end
      end)

      Req.default_options(plug: {Req.Test, MockHttp})

      start_link_supervised!(
        {TestSnowflakeRepo,
         [
           account_name: "test_acc",
           username: "test_usr",
           private_key_path: private_key_path,
           public_key_fingerprint:
             "4dfd2c71b73c0c5a600c5e96004ca52204dfd74632e8e53738770538f7b8af5c",
           role: "fake_role",
           warehouse: "fake_warehouse"
         ]}
      )

      :ok
    end

    test "http connection errors from ecto query_many should surface granular errors" do
      # Capture logs with metadata to verify Logger.metadata is working
      logs =
        capture_log([metadata: :all], fn ->
          assert_raise Snowflex.Error, "Server too busy. Please retry.", fn ->
            TestSnowflakeRepo.query_many!("SELECT * from THIS_MUST_ERROR")
          end
        end)

      # Assert all expected metadata is present in logs
      assert logs =~ "snowflex_account_name=test_acc"
      assert logs =~ "snowflex_username=test_usr"
      assert logs =~ "snowflex_warehouse=fake_warehouse"
      assert logs =~ "snowflex_role=fake_role"
      assert logs =~ "snowflex_statement=SELECT * from THIS_MUST_ERROR"
      assert logs =~ "snowflex_query_id=01b7e043-0206-7a43-0008-8b8300073d86"

      # Verify the error log itself appears
      assert logs =~ "QUERY ERROR"
    end

    test "http connection errors from ecto .all() should surface granular errors" do
      # Capture logs with metadata to verify Logger.metadata is working
      logs =
        capture_log([metadata: :all], fn ->
          assert_raise Snowflex.Error, "Server too busy. Please retry.", fn ->
            TestSnowflakeRepo.all(TestSchema)
          end
        end)

      # Assert all expected metadata is present in logs
      assert logs =~ "snowflex_account_name=test_acc"
      assert logs =~ "snowflex_username=test_usr"
      assert logs =~ "snowflex_warehouse=fake_warehouse"
      assert logs =~ "snowflex_role=fake_role"

      assert logs =~
               "snowflex_statement=SELECT s0.id, s0.x, s0.y, s0.z, s0.meta FROM schema AS s0"

      assert logs =~ "snowflex_query_id=01b7e043-0206-7a43-0008-8b8300073d86"

      # Verify the error log itself appears
      assert logs =~ "QUERY ERROR"
    end
  end
end
