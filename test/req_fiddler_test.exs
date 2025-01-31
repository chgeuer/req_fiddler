defmodule ReqFiddlerTest do
  use ExUnit.Case
  doctest ReqFiddler

  test "greets the world" do
    assert ReqFiddler.hello() == :world
  end
end
