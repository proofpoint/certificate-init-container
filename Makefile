TAG = $(shell git describe --tags --always)
PREFIX = $(shell git config --get remote.origin.url | sed 's/\(.*\).git/\1/' | tr ':.' '/'  | rev | cut -d '/' -f 2 | rev)
REPO_NAME = $(shell git config --get remote.origin.url | sed 's/\(.*\).git/\1/' | tr ':.' '/'  | rev | cut -d '/' -f 1 | rev)

all: build push

build:
	CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo

container: image

image:
	docker build -t $(PREFIX)/$(REPO_NAME) . # Build new image and automatically tag it as latest
	docker tag $(PREFIX)/$(REPO_NAME) $(PREFIX)/$(REPO_NAME):$(TAG)  # Add the version tag to the latest image

push: image
	docker push $(PREFIX)/$(REPO_NAME) # Push image tagged as latest to repository
	docker push $(PREFIX)/$(REPO_NAME):$(TAG) # Push version tagged image to repository (since this image is already pushed it will simply create or update version tag)

clean:
