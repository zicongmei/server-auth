# Image configuration
DOCKER_USER = zicongmei
IMAGE_NAME = reverse-proxy
TAG = latest
FULL_IMAGE_NAME = $(DOCKER_USER)/$(IMAGE_NAME):$(TAG)

.PHONY: all build docker-build push clean

all: build

build:
	go build -o reverse-proxy-bin main.go

docker-build:
	docker build -t $(FULL_IMAGE_NAME) .

push: docker-build
	docker push $(FULL_IMAGE_NAME)

clean:
	rm -f reverse-proxy-bin
	docker rmi $(FULL_IMAGE_NAME) || true
