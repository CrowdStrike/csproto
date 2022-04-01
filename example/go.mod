module github.com/CrowdStrike/csproto/example

go 1.18

require (
	github.com/CrowdStrike/csproto v0.0.0
	github.com/gofrs/uuid v4.2.0+incompatible
	github.com/gogo/protobuf v1.3.2
	google.golang.org/protobuf v1.27.1
)

require github.com/golang/protobuf v1.5.2

replace github.com/CrowdStrike/csproto => ../
