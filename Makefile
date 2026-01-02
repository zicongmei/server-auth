.PHONY: build push

IMAGE_NAME := zicongmei/server-auth

build:
	docker build -t $(IMAGE_NAME) .

push: build
	docker push $(IMAGE_NAME)