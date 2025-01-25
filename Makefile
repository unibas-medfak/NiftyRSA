SWIFT_VERSION = 6.0

format:
	xcrun swift-format . --recursive --in-place

doc:
	swift package --disable-sandbox preview-documentation --target NiftyRSA

docker-build:
	docker run \
		--rm \
		-v "$(PWD):$(PWD)" \
		-w "$(PWD)" \
		swift:$(SWIFT_VERSION) \
		bash -c "swift build"

PHONY: format doc
