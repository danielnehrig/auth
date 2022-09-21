
swag:
	protoc -I /usr/local/include -I . \
	        -I $(HOME)/go/pkg/mod \
		-I ./googleapis \
		--swagger_out=logtostderr=true:. \
		./proto/auth.proto

help: ## Prints help for targets with comments
	@cat $(MAKEFILE_LIST) | grep -E '^[a-zA-Z_-]+:.*?## .*$$' | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
