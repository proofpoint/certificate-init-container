FROM       golang:1.13
ADD        . /go/src/github.com/proofpoint/certificate-init-container
RUN        go install github.com/proofpoint/certificate-init-container && \
           go test github.com/proofpoint/certificate-init-container/...

FROM debian:10.1-slim

COPY --from=0 /go/bin/certificate-init-container .
USER 1000
ENTRYPOINT ["/certificate-init-container"]
