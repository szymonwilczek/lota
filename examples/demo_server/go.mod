module github.com/szymonwilczek/lota/examples/demo_server

go 1.24.0

require (
	github.com/google/uuid v1.6.0
	github.com/szymonwilczek/lota/sdk/server v0.0.0-00010101000000-000000000000
)

replace github.com/szymonwilczek/lota/sdk/server => ../../src/sdk/server
