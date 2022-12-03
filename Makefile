DOCKER_IMAGE = baxter/baxnapalm
DOCKER_VER = 1.1.1

.PHONY: build
build:
	docker build -t $(DOCKER_IMAGE):$(DOCKER_VER) .
	docker tag $(DOCKER_IMAGE):$(DOCKER_VER) $(DOCKER_IMAGE):latest

.PHONY: tests
tests: 
	docker run $(DOCKER_IMAGE):$(DOCKER_VER) pytest -v
