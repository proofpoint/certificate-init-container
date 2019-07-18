FROM       golang:1.12
ADD        . /go/src/github.com/proofpoint/certificate-init-container
RUN        go install github.com/proofpoint/certificate-init-container && \
           go test github.com/proofpoint/certificate-init-container/...

FROM debian:10.0-slim

COPY --from=0 /go/bin/certificate-init-container .
ENTRYPOINT ["/certificate-init-container"]
